import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI WarpOut at (129, 249)
	pWarpOut = App.PlainAI_Create(pShip, "WarpOut")
	pWarpOut.SetScriptModule("Warp")
	pWarpOut.SetInterruptable(1)
	# Done creating PlainAI WarpOut
	#########################################
	#########################################
	# Creating ConditionalAI StationDead at (127, 207)
	## Conditions:
	#### Condition StationInSet
	pStationInSet = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", "Litvok Nor", "Alioth6")
	## Evaluation function:
	def EvalFunc(bStationInSet):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if(bStationInSet):
			return DORMANT
		return ACTIVE
	## The ConditionalAI:
	pStationDead = App.ConditionalAI_Create(pShip, "StationDead")
	pStationDead.SetInterruptable(1)
	pStationDead.SetContainedAI(pWarpOut)
	pStationDead.AddCondition(pStationInSet)
	pStationDead.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI StationDead
	#########################################
	#########################################
	# Creating PlainAI Intercept at (356, 322)
	pIntercept = App.PlainAI_Create(pShip, "Intercept")
	pIntercept.SetScriptModule("Intercept")
	pIntercept.SetInterruptable(1)
	pScript = pIntercept.GetScriptInstance()
	pScript.SetTargetObjectName("player")
	# Done creating PlainAI Intercept
	#########################################
	#########################################
	# Creating ConditionalAI Delay at (315, 286)
	## Conditions:
	#### Condition TimerElapsed
	pTimerElapsed = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 20)
	## Evaluation function:
	def EvalFunc(bTimerElapsed):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if(bTimerElapsed):
			return DONE
		return ACTIVE
	## The ConditionalAI:
	pDelay = App.ConditionalAI_Create(pShip, "Delay")
	pDelay.SetInterruptable(1)
	pDelay.SetContainedAI(pIntercept)
	pDelay.AddCondition(pTimerElapsed)
	pDelay.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI Delay
	#########################################
	#########################################
	# Creating CompoundAI Attack at (372, 252)
	import Ai.Compound.BasicAttack
	pAttack = Ai.Compound.BasicAttack.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode7.E7M6.E7M6", "pFriendlies"), Difficulty = 0.85)
	# Done creating CompoundAI Attack
	#########################################
	#########################################
	# Creating SequenceAI Sequence at (225, 201)
	pSequence = App.SequenceAI_Create(pShip, "Sequence")
	pSequence.SetInterruptable(1)
	pSequence.SetLoopCount(1)
	pSequence.SetResetIfInterrupted(1)
	pSequence.SetDoubleCheckAllDone(0)
	pSequence.SetSkipDormant(0)
	# SeqBlock is at (306, 259)
	pSequence.AddAI(pDelay)
	pSequence.AddAI(pAttack)
	# Done creating SequenceAI Sequence
	#########################################
	#########################################
	# Creating PlainAI Stay at (331, 208)
	pStay = App.PlainAI_Create(pShip, "Stay")
	pStay.SetScriptModule("Stay")
	pStay.SetInterruptable(1)
	# Done creating PlainAI Stay
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (218, 119)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (241, 151)
	pPriorityList.AddAI(pStationDead, 1)
	pPriorityList.AddAI(pSequence, 2)
	pPriorityList.AddAI(pStay, 3)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (218, 80)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pPriorityList)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	#########################################
	# Creating PreprocessingAI RedAlert at (217, 23)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AlertLevel(App.ShipClass.RED_ALERT)
	## The PreprocessingAI:
	pRedAlert = App.PreprocessingAI_Create(pShip, "RedAlert")
	pRedAlert.SetInterruptable(1)
	pRedAlert.SetPreprocessingMethod(pScript, "Update")
	pRedAlert.SetContainedAI(pAvoidObstacles)
	# Done creating PreprocessingAI RedAlert
	#########################################
	return pRedAlert
