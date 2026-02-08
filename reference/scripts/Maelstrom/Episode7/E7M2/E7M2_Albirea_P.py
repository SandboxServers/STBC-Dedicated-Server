import App

def LoadPlacements(sSetName):
	# Position "Player Start"
	kThis = App.Waypoint_Create("Player Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(0.064856, -9.354877, 2.359643)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.063956, 0.997314, 0.035700)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.001987, -0.035646, 0.999363)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Player Start"

	# Position "Station Start"
	kThis = App.Waypoint_Create("Station Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-2.324634, 118.480637, 4.922688)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.053900, -0.998519, 0.007391)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.025848, 0.008794, 0.999627)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Station Start"

	# Position "Warbird Start"
	kThis = App.Waypoint_Create("Warbird Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-8.102109, 27.515141, 3.456827)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.308164, -0.951198, -0.016038)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.102882, -0.050081, 0.993432)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Warbird Start"

	# Position "Vorcha Start"
	kThis = App.Waypoint_Create("Vorcha Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(10.760961, 26.932966, 3.618836)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.324774, -0.944920, -0.040596)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.023314, -0.050908, 0.998431)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Vorcha Start"

	# Position "Enemy1 Start"
	kThis = App.Waypoint_Create("Enemy1 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(37.428940, 627.953125, 16.793289)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.124944, -0.991865, -0.024347)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000005, 0.024540, 0.999699)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Enemy1 Start"

	# Position "Enemy2 Start"
	kThis = App.Waypoint_Create("Enemy2 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-8.598532, 642.195068, 17.140966)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.124944, -0.991865, -0.024347)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000005, 0.024540, 0.999699)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Enemy2 Start"

	# Position "Enemy3 Start"
	kThis = App.Waypoint_Create("Enemy3 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(95.369865, 625.624329, 16.739197)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.124944, -0.991865, -0.024347)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000005, 0.024540, 0.999699)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Enemy3 Start"

	# Position "Enemy1 Way1"
	kThis = App.Waypoint_Create("Enemy1 Way1", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(6.537314, 417.509094, 12.991589)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.124944, -0.991865, -0.024347)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000005, 0.024540, 0.999699)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(4.000000)
	kThis.Update(0)
	kThis = None
	# End position "Enemy1 Way1"

	# Position "Enemy2 Way1"
	kThis = App.Waypoint_Create("Enemy2 Way1", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-42.390896, 445.594208, 13.678986)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.124944, -0.991865, -0.024347)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000005, 0.024540, 0.999699)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(4.000000)
	kThis.Update(0)
	kThis = None
	# End position "Enemy2 Way1"

	# Position "Enemy3 Way1"
	kThis = App.Waypoint_Create("Enemy3 Way1", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(60.282509, 419.255280, 13.036491)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.124944, -0.991865, -0.024347)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000005, 0.024540, 0.999699)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(4.000000)
	kThis.Update(0)
	kThis = None
	# End position "Enemy3 Way1"

	# Position "Warbird Way1"
	kThis = App.Waypoint_Create("Warbird Way1", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-50.498444, -158.705612, 11.605355)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.096745, -0.991582, 0.086056)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.017495, 0.084754, 0.996248)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(5.000000)
	kThis.Update(0)
	kThis = None
	# End position "Warbird Way1"

	# Position "Vorcha Way1"
	kThis = App.Waypoint_Create("Vorcha Way1", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(47.340023, -161.550491, 8.280628)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.149605, -0.988724, 0.006562)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.007394, 0.005518, 0.999957)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(5.000000)
	kThis.Update(0)
	kThis = None
	# End position "Vorcha Way1"

	# Position "CloakCamera1"
	kThis = App.Waypoint_Create("CloakCamera1", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-2.106918, 16.872555, 74.665810)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000242, -0.074694, -0.997206)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000260, 0.997206, -0.074694)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "CloakCamera1"

	# Position "CloakCamera2"
	kThis = App.Waypoint_Create("CloakCamera2", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(1.871003, -8.766197, 3.784423)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.019546, 0.992283, -0.122443)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.006425, 0.122339, 0.992468)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "CloakCamera2"

	# Attaching object "CloakCamera1" after "CloakCamera1"...
	kThis = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "CloakCamera1") )
	kPrevious = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "CloakCamera1") )
	kThis.InsertAfterObj( kPrevious )
	kThis = kPrevious = None
	# Attaching object "CloakCamera2" after "CloakCamera2"...
	kThis = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "CloakCamera2") )
	kPrevious = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "CloakCamera2") )
	kThis.InsertAfterObj( kPrevious )
	kThis = kPrevious = None
