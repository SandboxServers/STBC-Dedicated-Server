import App

def CreateAI(pShip, sWaypoint):
	#########################################
	# Creating PlainAI WarpIn at (161, 227)
	pWarpIn = App.PlainAI_Create(pShip, "WarpIn")
	pWarpIn.SetScriptModule("Warp")
	pWarpIn.SetInterruptable(1)
	pScript = pWarpIn.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.Ascella.Ascella3")
	pScript.SetDestinationPlacementName(sWaypoint)
	pScript.SetWarpDuration(0)
	pScript.WarpBlindly(1)
	# Done creating PlainAI WarpIn
	#########################################
	#########################################
	# Creating ConditionalAI Delay at (162, 181)
	## Conditions:
	#### Condition TimerElapsed
	pTimerElapsed = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 200)
	## Evaluation function:
	def EvalFunc(bTimerElapsed):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bTimerElapsed:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pDelay = App.ConditionalAI_Create(pShip, "Delay")
	pDelay.SetInterruptable(1)
	pDelay.SetContainedAI(pWarpIn)
	pDelay.AddCondition(pTimerElapsed)
	pDelay.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI Delay
	#########################################
	#########################################
	# Creating CompoundAI Attack at (295, 292)
	import AI.Compound.BasicAttack
	pAttack = AI.Compound.BasicAttack.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode7.E7M3.E7M3", "pFriendlies"))
	# Done creating CompoundAI Attack
	#########################################
	#########################################
	# Creating ConditionalAI Range at (296, 248)
	## Conditions:
	#### Condition InRange
	pInRange = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 257, pShip.GetName(), App.ObjectGroup_FromModule("Maelstrom.Episode7.E7M3.E7M3", "pFriendlies"))
	## Evaluation function:
	def EvalFunc(bInRange):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bInRange:
			return ACTIVE
		else:
			return DORMANT
	## The ConditionalAI:
	pRange = App.ConditionalAI_Create(pShip, "Range")
	pRange.SetInterruptable(1)
	pRange.SetContainedAI(pAttack)
	pRange.AddCondition(pInRange)
	pRange.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI Range
	#########################################
	#########################################
	# Creating PlainAI Intercept at (409, 248)
	pIntercept = App.PlainAI_Create(pShip, "Intercept")
	pIntercept.SetScriptModule("Intercept")
	pIntercept.SetInterruptable(1)
	pScript = pIntercept.GetScriptInstance()
	pScript.SetTargetObjectName("player")
	pScript.SetInterceptDistance(0)
	# Done creating PlainAI Intercept
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (349, 177)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (372, 207)
	pPriorityList.AddAI(pRange, 1)
	pPriorityList.AddAI(pIntercept, 2)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating SequenceAI Sequence at (247, 102)
	pSequence = App.SequenceAI_Create(pShip, "Sequence")
	pSequence.SetInterruptable(1)
	pSequence.SetLoopCount(1)
	pSequence.SetResetIfInterrupted(1)
	pSequence.SetDoubleCheckAllDone(0)
	pSequence.SetSkipDormant(0)
	# SeqBlock is at (275, 133)
	pSequence.AddAI(pDelay)
	pSequence.AddAI(pPriorityList)
	# Done creating SequenceAI Sequence
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (247, 48)
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
