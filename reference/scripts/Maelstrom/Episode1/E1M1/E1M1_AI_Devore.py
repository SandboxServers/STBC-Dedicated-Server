import App

def CreateAI(pShip):
	#########################################
	# Creating PlainAI FlyOut at (91, 102)
	pFlyOut = App.PlainAI_Create(pShip, "FlyOut")
	pFlyOut.SetScriptModule("FollowWaypoints")
	pFlyOut.SetInterruptable(1)
	pScript = pFlyOut.GetScriptInstance()
	pScript.SetTargetWaypointName("Docking Exit End")
	# Done creating PlainAI FlyOut
	#########################################
	#########################################
	# Creating PlainAI OrbitStarbase at (209, 77)
	pOrbitStarbase = App.PlainAI_Create(pShip, "OrbitStarbase")
	pOrbitStarbase.SetScriptModule("CircleObject")
	pOrbitStarbase.SetInterruptable(1)
	pScript = pOrbitStarbase.GetScriptInstance()
	pScript.SetFollowObjectName("Starbase 12")
	pScript.SetNearFacingVector(App.TGPoint3_GetModelLeft())
	pScript.SetRoughDistances(300, 350)
	pScript.SetCircleSpeed(0.2)
	# Done creating PlainAI OrbitStarbase
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (208, 131)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pOrbitStarbase)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	#########################################
	# Creating SequenceAI Sequence at (37, 184)
	pSequence = App.SequenceAI_Create(pShip, "Sequence")
	pSequence.SetInterruptable(1)
	pSequence.SetLoopCount(1)
	pSequence.SetResetIfInterrupted(1)
	pSequence.SetDoubleCheckAllDone(0)
	pSequence.SetSkipDormant(0)
	# SeqBlock is at (165, 171)
	pSequence.AddAI(pFlyOut)
	pSequence.AddAI(pAvoidObstacles)
	# Done creating SequenceAI Sequence
	#########################################
	#########################################
	# Creating PreprocessingAI GreenAlert at (35, 237)
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
	return pGreenAlert
