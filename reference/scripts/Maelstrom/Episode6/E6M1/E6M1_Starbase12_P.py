import App

def LoadPlacements(sSetName):
	# Position "CutScene0"
	kThis = App.Waypoint_Create("CutScene0", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(108.620598, -97.037125, 36.045040)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.821399, -0.438609, -0.364590)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.416827, 0.025313, 0.908634)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(0.001000)
	kThis.Update(0)
	kThis = None
	# End position "CutScene0"

	# Position "CutScene1"
	kThis = App.Waypoint_Create("CutScene1", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(108.620598, -97.037125, 36.045040)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.821399, -0.438609, -0.364590)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.416827, 0.025313, 0.908634)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(0.001000)
	kThis.Update(0)
	kThis = None
	# End position "CutScene1"

	# Position "CutScene1a"
	kThis = App.Waypoint_Create("CutScene1a", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(74.713966, -118.870201, 28.324030)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.811641, -0.536579, -0.230917)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.325717, 0.087554, 0.941405)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "CutScene1a"

	# Position "CutScene2"
	kThis = App.Waypoint_Create("CutScene2", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-34.325623, -189.539520, 4.801919)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.029751, 0.991092, -0.129811)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.023887, 0.129127, 0.991340)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(0.001000)
	kThis.Update(0)
	kThis = None
	# End position "CutScene2"

	# Position "CutScene2a"
	kThis = App.Waypoint_Create("CutScene2a", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-34.325623, -189.539520, 4.801919)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.029751, 0.991092, -0.129811)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.023887, 0.129127, 0.991340)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(0.001000)
	kThis.Update(0)
	kThis = None
	# End position "CutScene2a"

	# Position "CutScene2b"
	kThis = App.Waypoint_Create("CutScene2b", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-48.809525, -148.946884, -11.801521)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.901888, -0.045187, 0.429601)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.413268, 0.199213, 0.888552)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "CutScene2b"

	# Position "CutScene3"
	kThis = App.Waypoint_Create("CutScene3", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-89.910599, 446.412445, -42.883541)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.094978, -0.983445, -0.154323)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.052003, -0.149911, 0.987331)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(0.001000)
	kThis.Update(0)
	kThis = None
	# End position "CutScene3"

	# Attaching object "CutScene1a" after "CutScene1"...
	kThis = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "CutScene1") )
	kPrevious = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "CutScene1a") )
	kThis.InsertAfterObj( kPrevious )
	kThis = kPrevious = None
	# Attaching object "CutScene2" after "CutScene1a"...
	kThis = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "CutScene1a") )
	kPrevious = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "CutScene2") )
	kThis.InsertAfterObj( kPrevious )
	kThis = kPrevious = None
	# Attaching object "CutScene2b" after "CutScene2a"...
	kThis = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "CutScene2a") )
	kPrevious = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "CutScene2b") )
	kThis.InsertAfterObj( kPrevious )
	kThis = kPrevious = None
	# Attaching object "CutScene3" after "CutScene2b"...
	kThis = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "CutScene2b") )
	kPrevious = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "CutScene3") )
	kThis.InsertAfterObj( kPrevious )
	kThis = kPrevious = None


