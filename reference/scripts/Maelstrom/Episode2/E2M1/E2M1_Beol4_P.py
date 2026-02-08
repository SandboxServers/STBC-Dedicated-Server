import App

def LoadPlacements(sSetName):
	# Position "Karoon Start"
	kThis = App.Waypoint_Create("Karoon Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(548.725708, 527.130737, 543.881409)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.008935, 0.508017, 0.861301)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.063556, -0.859882, 0.506521)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Karoon Start"

	# Position "WarbirdStart"
	kThis = App.Waypoint_Create("WarbirdStart", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(548.972778, 541.208984, 567.750305)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.008935, 0.508017, 0.861301)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.063556, -0.859882, 0.506521)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "WarbirdStart"

	# Position "AsteroidP 0"
	kThis = App.Waypoint_Create("AsteroidP 0", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(545.063477, 591.850586, 876.861145)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.900236, 0.370553, 0.228619)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.435390, 0.762016, 0.479341)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "AsteroidP 0"

	# Position "AsteroidP 1"
	kThis = App.Waypoint_Create("AsteroidP 1", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(478.217102, 659.567017, 741.012512)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.040495, 0.508850, 0.859902)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.723452, -0.608538, 0.326035)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "AsteroidP 1"

	# Position "AsteroidP 2"
	kThis = App.Waypoint_Create("AsteroidP 2", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(511.404510, 599.470337, 919.070984)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.040495, 0.508850, 0.859902)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.576037, -0.715084, 0.396026)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "AsteroidP 2"

	# Position "AsteroidP 3"
	kThis = App.Waypoint_Create("AsteroidP 3", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(569.919250, 696.812439, 904.473755)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.574870, 0.530653, 0.622841)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.550868, -0.813843, 0.184944)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "AsteroidP 3"

	# Position "AsteroidP 4"
	kThis = App.Waypoint_Create("AsteroidP 4", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(591.048462, 745.152222, 880.617676)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.425975, -0.786210, 0.447682)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.624906, -0.613502, -0.482813)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "AsteroidP 4"

	# Position "AsteroidP 5"
	kThis = App.Waypoint_Create("AsteroidP 5", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(645.674133, 772.930237, 901.388062)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.366852, -0.838289, -0.403349)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.874497, 0.458636, -0.157825)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "AsteroidP 5"

	# Position "AsteroidP 6"
	kThis = App.Waypoint_Create("AsteroidP 6", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(639.535645, 752.248657, 946.542908)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.786347, -0.391939, -0.477537)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.610842, -0.608835, -0.506154)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "AsteroidP 6"

	# Position "AsteroidP 7"
	kThis = App.Waypoint_Create("AsteroidP 7", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(608.129150, 719.158997, 967.534851)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.907735, -0.392410, -0.148432)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.401628, -0.710483, -0.577848)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "AsteroidP 7"

	# Position "AsteroidP 8"
	kThis = App.Waypoint_Create("AsteroidP 8", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(598.625122, 685.790283, 989.319336)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.580411, 0.454048, -0.675991)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.487771, -0.470882, -0.735085)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "AsteroidP 8"

	# Position "AsteroidP 9"
	kThis = App.Waypoint_Create("AsteroidP 9", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(574.807556, 631.687500, 994.843933)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.072558, 0.885614, -0.458719)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.771381, -0.341378, -0.537059)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "AsteroidP 9"

	# Position "AsteroidP 10"
	kThis = App.Waypoint_Create("AsteroidP 10", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(565.374023, 693.026550, 954.816345)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.050732, 0.915136, -0.399941)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.780164, -0.213698, -0.587943)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "AsteroidP 10"

	# Position "AsteroidP 11"
	kThis = App.Waypoint_Create("AsteroidP 11", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(584.707214, 608.584900, 844.972290)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.521145, -0.301859, -0.798304)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.694976, -0.693024, -0.191641)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "AsteroidP 11"

	# Position "AsteroidP 12"
	kThis = App.Waypoint_Create("AsteroidP 12", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(493.080719, 657.823364, 904.429321)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.773047, 0.622112, 0.123992)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.634293, -0.755493, -0.164020)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "AsteroidP 12"

	# Position "AsteroidP 13"
	kThis = App.Waypoint_Create("AsteroidP 13", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(495.319641, 675.450317, 861.009460)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.619100, 0.637535, 0.458546)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.714611, -0.699480, 0.007693)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "AsteroidP 13"

	# Position "AsteroidP 14"
	kThis = App.Waypoint_Create("AsteroidP 14", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(524.611938, 719.528564, 818.041992)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.210655, 0.198752, 0.957143)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.468318, -0.879962, 0.079654)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "AsteroidP 14"

	# Position "AsteroidP 15"
	kThis = App.Waypoint_Create("AsteroidP 15", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(594.002686, 712.989441, 854.304321)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.615964, 0.102877, 0.781028)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.482135, -0.833300, -0.270477)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "AsteroidP 15"

	# Position "WarbirdWay1"
	kThis = App.Waypoint_Create("WarbirdWay1", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(589.987854, 740.274780, 921.039978)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.886477, 0.071884, 0.457156)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.192878, -0.840580, 0.506186)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "WarbirdWay1"

	# Position "KaroonExit"
	kThis = App.Waypoint_Create("KaroonExit", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(639.536743, 230.622437, 361.168335)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.224177, 0.558487, 0.798647)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.248782, 0.825148, -0.507186)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(0.050000)
	kThis.Update(0)
	kThis = None
	# End position "KaroonExit"

