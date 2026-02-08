import App
def CreateAI(pShip, sPlacementName):
	#########################################
	# Creating PlainAI FlyToEscapePoint at (114, 144)
	pFlyToEscapePoint = App.PlainAI_Create(pShip, "FlyToEscapePoint")
	pFlyToEscapePoint.SetScriptModule("FollowWaypoints")
	pFlyToEscapePoint.SetInterruptable(1)
	pScript = pFlyToEscapePoint.GetScriptInstance()
	pScript.SetTargetWaypointName("ShuttleEscapePoint")
	# Done creating PlainAI FlyToEscapePoint
	#########################################
	#########################################
	# Creating PlainAI WarpToBeol4 at (224, 145)
	pWarpToBeol4 = App.PlainAI_Create(pShip, "WarpToBeol4")
	pWarpToBeol4.SetScriptModule("Warp")
	pWarpToBeol4.SetInterruptable(1)
	pScript = pWarpToBeol4.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.Beol.Beol4")
	pScript.SetDestinationPlacementName(sPlacementName)
	pScript.SetWarpDuration(2)
	# Done creating PlainAI WarpToBeol4
	#########################################
	#########################################
	# Creating SequenceAI Sequence at (76, 217)
	pSequence = App.SequenceAI_Create(pShip, "Sequence")
	pSequence.SetInterruptable(1)
	pSequence.SetLoopCount(1)
	pSequence.SetResetIfInterrupted(1)
	pSequence.SetDoubleCheckAllDone(0)
	pSequence.SetSkipDormant(0)
	# SeqBlock is at (185, 212)
	pSequence.AddAI(pFlyToEscapePoint)
	pSequence.AddAI(pWarpToBeol4)
	# Done creating SequenceAI Sequence
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (76, 283)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pSequence)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
