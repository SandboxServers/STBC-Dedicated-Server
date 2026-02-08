import App

def CreateAI(pShip):
	#########################################
	# Creating PlainAI FlyToWayPoints at (75, 62)
	pFlyToWayPoints = App.PlainAI_Create(pShip, "FlyToWayPoints")
	pFlyToWayPoints.SetScriptModule("FollowWaypoints")
	pFlyToWayPoints.SetInterruptable(1)
	pScript = pFlyToWayPoints.GetScriptInstance()
	pScript.SetTargetWaypointName("Way 1")
	# Done creating PlainAI FlyToWayPoints
	#########################################
	#########################################
	# Creating ConditionalAI HalfMinuteTimer at (73, 113)
	## Conditions:
	#### Condition HalfMinute
	pHalfMinute = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 30)
	## Evaluation function:
	def EvalFunc(bHalfMinute):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bHalfMinute:
			return DONE
		return ACTIVE
	## The ConditionalAI:
	pHalfMinuteTimer = App.ConditionalAI_Create(pShip, "HalfMinuteTimer")
	pHalfMinuteTimer.SetInterruptable(1)
	pHalfMinuteTimer.SetContainedAI(pFlyToWayPoints)
	pHalfMinuteTimer.AddCondition(pHalfMinute)
	pHalfMinuteTimer.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI HalfMinuteTimer
	#########################################
	#########################################
	# Creating PlainAI StayPut at (180, 63)
	pStayPut = App.PlainAI_Create(pShip, "StayPut")
	pStayPut.SetScriptModule("Stay")
	pStayPut.SetInterruptable(1)
	# Done creating PlainAI StayPut
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (180, 115)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pStayPut)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	#########################################
	# Creating SequenceAI Sequence at (27, 198)
	pSequence = App.SequenceAI_Create(pShip, "Sequence")
	pSequence.SetInterruptable(1)
	pSequence.SetLoopCount(1)
	pSequence.SetResetIfInterrupted(1)
	pSequence.SetDoubleCheckAllDone(0)
	pSequence.SetSkipDormant(0)
	# SeqBlock is at (126, 179)
	pSequence.AddAI(pHalfMinuteTimer)
	pSequence.AddAI(pAvoidObstacles)
	# Done creating SequenceAI Sequence
	#########################################
	return pSequence
