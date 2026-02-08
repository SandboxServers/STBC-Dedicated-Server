import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI WarpToStarbase at (118, 86)
	pWarpToStarbase = App.PlainAI_Create(pShip, "WarpToStarbase")
	pWarpToStarbase.SetScriptModule("Warp")
	pWarpToStarbase.SetInterruptable(1)
	pScript = pWarpToStarbase.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.Starbase12.Starbase12")
	pScript.SetDestinationPlacementName("NightEnter")
	pScript.SetWarpDuration(0.1)
	# Done creating PlainAI WarpToStarbase
	#########################################
	#########################################
	# Creating PlainAI FlyToWaypoint at (230, 84)
	pFlyToWaypoint = App.PlainAI_Create(pShip, "FlyToWaypoint")
	pFlyToWaypoint.SetScriptModule("FollowWaypoints")
	pFlyToWaypoint.SetInterruptable(1)
	pScript = pFlyToWaypoint.GetScriptInstance()
	pScript.SetTargetWaypointName("NightWaypoint")
	# Done creating PlainAI FlyToWaypoint
	#########################################
	#########################################
	# Creating SequenceAI Sequence at (60, 172)
	pSequence = App.SequenceAI_Create(pShip, "Sequence")
	pSequence.SetInterruptable(1)
	pSequence.SetLoopCount(1)
	pSequence.SetResetIfInterrupted(1)
	pSequence.SetDoubleCheckAllDone(0)
	pSequence.SetSkipDormant(0)
	# SeqBlock is at (192, 141)
	pSequence.AddAI(pWarpToStarbase)
	pSequence.AddAI(pFlyToWaypoint)
	# Done creating SequenceAI Sequence
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (30, 265)
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
