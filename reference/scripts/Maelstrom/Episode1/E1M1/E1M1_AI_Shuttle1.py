import App

def CreateAI(pShip):
	#########################################
	# Creating PlainAI FlyWaypoints at (109, 160)
	pFlyWaypoints = App.PlainAI_Create(pShip, "FlyWaypoints")
	pFlyWaypoints.SetScriptModule("FollowWaypoints")
	pFlyWaypoints.SetInterruptable(1)
	pScript = pFlyWaypoints.GetScriptInstance()
	pScript.SetTargetWaypointName("Shuttle1Way1")
	# Done creating PlainAI FlyWaypoints
	#########################################
	#########################################
	# Creating PlainAI StayPut at (210, 115)
	pStayPut = App.PlainAI_Create(pShip, "StayPut")
	pStayPut.SetScriptModule("Stay")
	pStayPut.SetInterruptable(1)
	# Done creating PlainAI StayPut
	#########################################
	#########################################
	# Creating ConditionalAI TimerA at (208, 172)
	## Conditions:
	#### Condition ShortTimer
	pShortTimer = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 10, 1)
	## Evaluation function:
	def EvalFunc(bShortTimer):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bShortTimer:
			return DONE
		return ACTIVE
	## The ConditionalAI:
	pTimerA = App.ConditionalAI_Create(pShip, "TimerA")
	pTimerA.SetInterruptable(1)
	pTimerA.SetContainedAI(pStayPut)
	pTimerA.AddCondition(pShortTimer)
	pTimerA.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI TimerA
	#########################################
	#########################################
	# Creating SequenceAI Sequence at (50, 237)
	pSequence = App.SequenceAI_Create(pShip, "Sequence")
	pSequence.SetInterruptable(1)
	pSequence.SetLoopCount(-1)
	pSequence.SetResetIfInterrupted(1)
	pSequence.SetDoubleCheckAllDone(0)
	pSequence.SetSkipDormant(0)
	# SeqBlock is at (177, 227)
	pSequence.AddAI(pFlyWaypoints)
	pSequence.AddAI(pTimerA)
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
