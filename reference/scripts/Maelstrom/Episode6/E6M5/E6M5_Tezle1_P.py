import App

def LoadPlacements(sSetName):
	# Position "FedEnter"
	kThis = App.Waypoint_Create("FedEnter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-88.902336, 167.607101, 1.019485)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.003787, -0.998379, -0.056790)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.018143, -0.056712, 0.998226)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "FedEnter"

	# Position "KhitEnter"
	kThis = App.Waypoint_Create("KhitEnter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-60.564201, 167.036255, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.006433, -0.999468, -0.031962)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.324406, -0.032320, 0.945366)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "KhitEnter"

	# Position "ZhukovEnter"
	kThis = App.Waypoint_Create("ZhukovEnter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-25.184492, 168.666290, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.007518, -0.999476, 0.031483)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.037722, 0.031745, 0.998784)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "ZhukovEnter"

	# Position "Card1Enter"
	kThis = App.Waypoint_Create("Card1Enter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-458.260925, -82.559738, 4.900176)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.996717, 0.041303, 0.069636)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.062602, -0.152281, 0.986353)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Card1Enter"

	# Position "Card2Enter"
	kThis = App.Waypoint_Create("Card2Enter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-448.072510, -60.057217, -20.820223)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.983611, 0.122283, 0.132498)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.142618, 0.078059, 0.986695)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Card2Enter"

	# Position "Card3Enter"
	kThis = App.Waypoint_Create("Card3Enter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-468.784485, -37.627663, 32.092987)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.995766, 0.083449, 0.038543)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.021840, -0.622094, 0.782638)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Card3Enter"

	# Position "Card4Enter"
	kThis = App.Waypoint_Create("Card4Enter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(326.434326, -122.112770, -13.555262)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.668311, 0.742683, 0.042216)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.021075, -0.037825, 0.999062)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Card4Enter"

	# Position "Card5Enter"
	kThis = App.Waypoint_Create("Card5Enter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(318.592499, -149.730392, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.681599, 0.731562, -0.015511)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.001901, 0.019428, 0.999809)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Card5Enter"

	# Position "Card6Enter"
	kThis = App.Waypoint_Create("Card6Enter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(302.952118, -173.177658, -12.669350)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.784749, 0.619592, -0.016589)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.005552, 0.019736, 0.999790)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Card6Enter"

	# Position "ShuttleLaunchPoint"
	kThis = App.Waypoint_Create("ShuttleLaunchPoint", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(5.142200, -160.194138, -3.084780)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.007722, 0.980636, -0.195686)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.127904, 0.195053, 0.972417)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "ShuttleLaunchPoint"

	# Position "ShuttleEscapePoint"
	kThis = App.Waypoint_Create("ShuttleEscapePoint", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(4.074741, -6.798556, -27.345688)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.006961, 0.987288, -0.158792)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.127961, 0.156611, 0.979336)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "ShuttleEscapePoint"

