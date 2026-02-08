import App

def CreateAI(pShip):
	#########################################
	# Creating PlainAI FlyWaypoints at (109, 160)
	pFlyWaypoints = App.PlainAI_Create(pShip, "FlyWaypoints")
	pFlyWaypoints.SetScriptModule("FollowWaypoints")
	pFlyWaypoints.SetInterruptable(1)
	pScript = pFlyWaypoints.GetScriptInstance()
	pScript.SetTargetWaypointName("Shuttle3Start")
	# Done creating PlainAI FlyWaypoints
	#########################################
	#########################################
	# Creating PlainAI OrbitStation at (214, 158)
	pOrbitStation = App.PlainAI_Create(pShip, "OrbitStation")
	pOrbitStation.SetScriptModule("CircleObject")
	pOrbitStation.SetInterruptable(1)
	pScript = pOrbitStation.GetScriptInstance()
	pScript.SetFollowObjectName("Station")
	pScript.SetNearFacingVector(App.TGPoint3_GetModelLeft())
	# Done creating PlainAI OrbitStation
	#########################################
	#########################################
	# Creating SequenceAI Sequence at (50, 237)
	pSequence = App.SequenceAI_Create(pShip, "Sequence")
	pSequence.SetInterruptable(1)
	pSequence.SetLoopCount(1)
	pSequence.SetResetIfInterrupted(1)
	pSequence.SetDoubleCheckAllDone(0)
	pSequence.SetSkipDormant(0)
	# SeqBlock is at (177, 227)
	pSequence.AddAI(pFlyWaypoints)
	pSequence.AddAI(pOrbitStation)
	# Done creating SequenceAI Sequence
	#########################################
	#########################################
	# Creating PreprocessingAI GreenAlert at (42, 293)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AlertLevel(App.ShipClass.GREEN_ALERT)
	## The PreprocessingAI:
	pGreenAlert = App.PreprocessingAI_Create(pShip, "GreenAlert")
	pGreenAlert.SetInterruptable(1)
	pGreenAlert.SetPreprocessingMethod(pScript, "Update")
	pGreenAlert.SetContainedAI(pSequence)
	# Done creating PreprocessingAI GreenAlert
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (42, 344)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pGreenAlert)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
