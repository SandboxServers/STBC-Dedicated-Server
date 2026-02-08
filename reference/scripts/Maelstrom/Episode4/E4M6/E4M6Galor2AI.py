import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI FollowWaypoint at (160, 181)
	pFollowWaypoint = App.PlainAI_Create(pShip, "FollowWaypoint")
	pFollowWaypoint.SetScriptModule("FollowWaypoints")
	pFollowWaypoint.SetInterruptable(1)
	pScript = pFollowWaypoint.GetScriptInstance()
	pScript.SetTargetWaypointName("Galor2 Warp")
	# Done creating PlainAI FollowWaypoint
	#########################################

	#########################################
	# Creating PlainAI CircleMatan at (281, 182)
	pCircleMatan = App.PlainAI_Create(pShip, "CircleMatan")
	pCircleMatan.SetScriptModule("CircleObject")
	pCircleMatan.SetInterruptable(1)
	pScript = pCircleMatan.GetScriptInstance()
	pScript.SetFollowObjectName("Keldon1")
	pScript.SetNearFacingVector(App.TGPoint3_GetModelLeft())
	pScript.SetRoughDistances(10, 20)
	pScript.SetCircleSpeed(1)
	# Done creating PlainAI CircleMatan
	#########################################
	#########################################
	# Creating SequenceAI Galor2AI at (231, 82)
	pGalor2AI = App.SequenceAI_Create(pShip, "Galor2AI")
	pGalor2AI.SetInterruptable(1)
	pGalor2AI.SetLoopCount(1)
	pGalor2AI.SetResetIfInterrupted(1)
	pGalor2AI.SetDoubleCheckAllDone(0)
	pGalor2AI.SetSkipDormant(0)
	# SeqBlock is at (255, 114)
	pGalor2AI.AddAI(pFollowWaypoint)
	pGalor2AI.AddAI(pCircleMatan)
	# Done creating SequenceAI Galor2AI
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (227, 33)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pGalor2AI)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
