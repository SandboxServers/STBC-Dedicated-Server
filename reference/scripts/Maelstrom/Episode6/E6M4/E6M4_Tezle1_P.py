import App

def LoadPlacements(sSetName):
	# Position "Keldon2Start"
	kThis = App.Waypoint_Create("Keldon2Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(321.604858, -138.007889, 35.137508)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.791508, 0.576368, -0.203262)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.109630, 0.193290, 0.974997)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Keldon2Start"

	# Position "Galor2Start"
	kThis = App.Waypoint_Create("Galor2Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(305.041870, -155.193558, -13.256783)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.717126, 0.696943, 0.000590)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.025346, -0.026926, 0.999316)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor2Start"

	# Position "Card1Enter"
	kThis = App.Waypoint_Create("Card1Enter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(35.942383, 195.298386, -0.066594)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.024611, -0.999697, 0.000403)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.006163, 0.000251, 0.999981)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Card1Enter"

	# Position "Card2Enter"
	kThis = App.Waypoint_Create("Card2Enter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(4.131048, 178.526199, 1.161463)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.105371, -0.994093, -0.026000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.050865, -0.031499, 0.998209)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Card2Enter"

	# Position "PlayerEnterTezle1"
	kThis = App.Waypoint_Create("PlayerEnterTezle1", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(218.404526, 902.455627, 25.703947)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.026582, -0.999567, 0.012609)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.531672, 0.024818, 0.846586)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "PlayerEnterTezle1"

