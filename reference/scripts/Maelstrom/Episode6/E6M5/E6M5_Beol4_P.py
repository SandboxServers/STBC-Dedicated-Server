import App

def LoadPlacements(sSetName):
	# Position "Shuttle3Enter"
	kThis = App.Waypoint_Create("Shuttle3Enter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(89.227974, 15.059155, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.389578, 0.920561, 0.028231)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.012647, -0.025303, 0.999600)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Shuttle3Enter"

	# Position "Shuttle4Enter"
	kThis = App.Waypoint_Create("Shuttle4Enter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(106.439888, 28.608957, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.517968, 0.853465, -0.057506)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.017964, 0.056359, 0.998249)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Shuttle4Enter"

	# Position "Shuttle2Enter"
	kThis = App.Waypoint_Create("Shuttle2Enter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(118.524841, 39.229076, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.414633, 0.908843, -0.045647)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.010704, 0.045288, 0.998917)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Shuttle2Enter"

	# Position "Shuttle1Enter"
	kThis = App.Waypoint_Create("Shuttle1Enter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(114.680679, 16.561050, 5.843839)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.636748, 0.768465, 0.063357)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.031458, -0.056210, 0.997923)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Shuttle1Enter"

	# Position "FedEnter"
	kThis = App.Waypoint_Create("FedEnter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-28.607695, 10.986631, -4.307706)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.055172, 0.000000, 0.998477)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "FedEnter"

	# Position "ZhukovEnter"
	kThis = App.Waypoint_Create("ZhukovEnter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(63.702404, -22.515934, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "ZhukovEnter"

	# Position "KhitEnter"
	kThis = App.Waypoint_Create("KhitEnter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(5.793441, 4.545355, 19.240002)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "KhitEnter"

