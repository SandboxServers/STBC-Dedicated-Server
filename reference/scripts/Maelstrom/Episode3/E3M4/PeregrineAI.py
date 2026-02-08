import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI CircletheStarbase at (125, 259)
	pCircletheStarbase = App.PlainAI_Create(pShip, "CircletheStarbase")
	pCircletheStarbase.SetScriptModule("CircleObject")
	pCircletheStarbase.SetInterruptable(1)
	pScript = pCircletheStarbase.GetScriptInstance()
	pScript.SetFollowObjectName("Starbase 12")
	pScript.SetNearFacingVector(App.TGPoint3_GetModelLeft())
	pScript.SetRoughDistances(150, 300)
	pScript.SetCircleSpeed(8)
	# Done creating PlainAI CircletheStarbase
	#########################################

	#########################################
	# Creating PreprocessingAI GreenAlert at (124, 212)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AlertLevel(App.ShipClass.GREEN_ALERT)
	## The PreprocessingAI:
	pGreenAlert = App.PreprocessingAI_Create(pShip, "GreenAlert")
	pGreenAlert.SetInterruptable(1)
	pGreenAlert.SetPreprocessingMethod(pScript, "Update")
	pGreenAlert.SetContainedAI(pCircletheStarbase)
	# Done creating PreprocessingAI GreenAlert
	#########################################
	#########################################
	# Creating ConditionalAI Timer at (123, 164)
	## Conditions:
	#### Condition TimerElapsed
	pTimerElapsed = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 5.0)
	## Evaluation function:
	def EvalFunc(bTimerElapsed):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bTimerElapsed:
			return DONE
		return ACTIVE
	## The ConditionalAI:
	pTimer = App.ConditionalAI_Create(pShip, "Timer")
	pTimer.SetInterruptable(1)
	pTimer.SetContainedAI(pGreenAlert)
	pTimer.AddCondition(pTimerElapsed)
	pTimer.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI Timer
	#########################################
	#########################################
	# Creating PlainAI WarpToNowhere at (234, 212)
	pWarpToNowhere = App.PlainAI_Create(pShip, "WarpToNowhere")
	pWarpToNowhere.SetScriptModule("Warp")
	pWarpToNowhere.SetInterruptable(1)
	# Done creating PlainAI WarpToNowhere
	#########################################
	#########################################
	# Creating PreprocessingAI RedAlert at (232, 165)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AlertLevel(App.ShipClass.RED_ALERT)
	## The PreprocessingAI:
	pRedAlert = App.PreprocessingAI_Create(pShip, "RedAlert")
	pRedAlert.SetInterruptable(1)
	pRedAlert.SetPreprocessingMethod(pScript, "Update")
	pRedAlert.SetContainedAI(pWarpToNowhere)
	# Done creating PreprocessingAI RedAlert
	#########################################
	#########################################
	# Creating SequenceAI Sequence at (167, 88)
	pSequence = App.SequenceAI_Create(pShip, "Sequence")
	pSequence.SetInterruptable(1)
	pSequence.SetLoopCount(1)
	pSequence.SetResetIfInterrupted(1)
	pSequence.SetDoubleCheckAllDone(0)
	pSequence.SetSkipDormant(0)
	# SeqBlock is at (192, 119)
	pSequence.AddAI(pTimer)
	pSequence.AddAI(pRedAlert)
	# Done creating SequenceAI Sequence
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (166, 42)
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
