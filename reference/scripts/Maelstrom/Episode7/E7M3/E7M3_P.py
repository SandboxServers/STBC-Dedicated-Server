import App

def LoadPlacements(sSetName):
	# Position "Outpost Location"
	kThis = App.Waypoint_Create("Outpost Location", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(97.604591, 202.583038, 4.666136)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.320484, -0.945791, -0.052626)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.043074, -0.070050, 0.996613)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Outpost Location"

	# Position "Player Start"
	kThis = App.Waypoint_Create("Player Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(97.604591, 550.583038, 4.666136)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.320484, -0.945791, -0.052626)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.043074, -0.070050, 0.996613)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "PLayer Start"

	# Position "Enemy1 Start"
	kThis = App.Waypoint_Create("Enemy1 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(50.087299, 241.719315, 11.767959)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.788898, -0.602382, -0.121556)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.086012, -0.087622, 0.992434)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Enemy1 Start"

	# Position "Enemy2 Start"
	kThis = App.Waypoint_Create("Enemy2 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(145.216782, 169.483704, -2.780830)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.830791, 0.550660, 0.081000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.049453, -0.071924, 0.996183)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Enemy2 Start"

	# Position "Enemy3 Start"
	kThis = App.Waypoint_Create("Enemy3 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(50.087299, 169.483704, 11.767959)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.788898, -0.602382, -0.121556)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.086012, -0.087622, 0.992434)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Enemy3 Start"

	# Position "Enemy4 Start"
	kThis = App.Waypoint_Create("Enemy4 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(145.216782, 241.719315, -2.780830)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.830791, 0.550660, 0.081000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.049453, -0.071924, 0.996183)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Enemy4 Start"
	
	# Position "Mine1 Location"
	kThis = App.Waypoint_Create("Mine1 Location", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(397.604591, 202.583038, 4.666136)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.320484, -0.945791, -0.052626)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.043074, -0.070050, 0.996613)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Mine1 Location"
	
	# Position "Mine2 Location"
	kThis = App.Waypoint_Create("Mine2 Location", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(90.604591, 472.583038, -14.666136)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.320484, -0.945791, -0.052626)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.043074, -0.070050, 0.996613)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Mine2 Location"

	# Position "Mine3 Location"
	kThis = App.Waypoint_Create("Mine3 Location", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(97.604591, 202.583038, 54.666136)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.320484, -0.945791, -0.052626)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.043074, -0.070050, 0.996613)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Mine3 Location"

	# Position "Mine4 Location"
	kThis = App.Waypoint_Create("Mine4 Location", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(147.604591, 202.583038, 4.666136)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.320484, -0.945791, -0.052626)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.043074, -0.070050, 0.996613)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Mine4 Location"
	
	# Position "Mine5 Location"
	kThis = App.Waypoint_Create("Mine5 Location", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(97.604591, 252.583038, 4.666136)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.320484, -0.945791, -0.052626)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.043074, -0.070050, 0.996613)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Mine5 Location"

	# Position "Mine6 Location"
	kThis = App.Waypoint_Create("Mine6 Location", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(87.604591, 232.583038, -204.666136)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.320484, -0.945791, -0.052626)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.043074, -0.070050, 0.996613)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Mine6 Location"

	# Position "Mine7 Location"
	kThis = App.Waypoint_Create("Mine7 Location", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(397.604591, 552.583038, 50.666136)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.320484, -0.945791, -0.052626)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.043074, -0.070050, 0.996613)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Mine7 Location"
	
	# Position "Mine8 Location"
	kThis = App.Waypoint_Create("Mine8 Location", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-107.604591, 452.583038, -90.666136)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.320484, -0.945791, -0.052626)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.043074, -0.070050, 0.996613)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Mine8 Location"

	# Position "Mine9 Location"
	kThis = App.Waypoint_Create("Mine9 Location", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-97.604591, 10.583038, 304.666136)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.320484, -0.945791, -0.052626)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.043074, -0.070050, 0.996613)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Mine9 Location"

	# Position "Mine10 Location"
	kThis = App.Waypoint_Create("Mine10 Location", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-150.604591, -52.583038, -94.666136)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.320484, -0.945791, -0.052626)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.043074, -0.070050, 0.996613)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Mine10 Location"
	
	# Position "Mine11 Location"
	kThis = App.Waypoint_Create("Mine11 Location", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(250.604591, -152.583038, 150.666136)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.320484, -0.945791, -0.052626)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.043074, -0.070050, 0.996613)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Mine11 Location"

	# Position "Mine12 Location"
	kThis = App.Waypoint_Create("Mine12 Location", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(50.604591, 152.583038, -324.666136)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.320484, -0.945791, -0.052626)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.043074, -0.070050, 0.996613)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Mine12 Location"

	# Position "Mine13 Location"
	kThis = App.Waypoint_Create("Mine13 Location", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(397.604591, 202.583038, -100.666136)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.320484, -0.945791, -0.052626)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.043074, -0.070050, 0.996613)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Mine13 Location"
	
	# Position "Mine14 Location"
	kThis = App.Waypoint_Create("Mine14 Location", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(90.604591, 472.583038, -114.666136)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.320484, -0.945791, -0.052626)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.043074, -0.070050, 0.996613)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Mine14 Location"

	# Position "Mine15 Location"
	kThis = App.Waypoint_Create("Mine15 Location", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(97.604591, 202.583038, -46.666136)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.320484, -0.945791, -0.052626)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.043074, -0.070050, 0.996613)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Mine15 Location"

	# Position "Mine16 Location"
	kThis = App.Waypoint_Create("Mine16 Location", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(47.604591, 202.583038, 4.666136)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.320484, -0.945791, -0.052626)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.043074, -0.070050, 0.996613)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Mine16 Location"

	# Position "Mine17 Location"
	kThis = App.Waypoint_Create("Mine17 Location", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(97.604591, 152.583038, 4.666136)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.320484, -0.945791, -0.052626)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.043074, -0.070050, 0.996613)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Mine17 Location"

	# Position "Mine18 Location"
	kThis = App.Waypoint_Create("Mine18 Location", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(87.604591, 232.583038, -104.666136)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.320484, -0.945791, -0.052626)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.043074, -0.070050, 0.996613)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Mine18 Location"

	# Position "Mine19 Location"
	kThis = App.Waypoint_Create("Mine19 Location", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(397.604591, 552.583038, -50.666136)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.320484, -0.945791, -0.052626)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.043074, -0.070050, 0.996613)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Mine19 Location"
	
	# Position "Mine20 Location"
	kThis = App.Waypoint_Create("Mine20 Location", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-107.604591, 452.583038, -190.666136)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.320484, -0.945791, -0.052626)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.043074, -0.070050, 0.996613)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Mine20 Location"

	# Position "Mine21 Location"
	kThis = App.Waypoint_Create("Mine21 Location", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-97.604591, 10.583038, 204.666136)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.320484, -0.945791, -0.052626)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.043074, -0.070050, 0.996613)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Mine21 Location"

	# Position "Mine22 Location"
	kThis = App.Waypoint_Create("Mine22 Location", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-150.604591, -52.583038, -194.666136)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.320484, -0.945791, -0.052626)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.043074, -0.070050, 0.996613)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Mine22 Location"
	
	# Position "Mine23 Location"
	kThis = App.Waypoint_Create("Mine23 Location", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(250.604591, -152.583038, 50.666136)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.320484, -0.945791, -0.052626)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.043074, -0.070050, 0.996613)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Mine23 Location"

	# Position "Mine24 Location"
	kThis = App.Waypoint_Create("Mine24 Location", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(50.604591, 152.583038, -224.666136)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.320484, -0.945791, -0.052626)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.043074, -0.070050, 0.996613)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Mine24 Location"

