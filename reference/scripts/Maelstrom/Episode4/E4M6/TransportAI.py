import App

def CreateAI(pShip):



	#########################################
	# Creating PlainAI Run at (118, 292)
	pRun = App.PlainAI_Create(pShip, "Run")
	pRun.SetScriptModule("Flee")
	pRun.SetInterruptable(1)
	pScript = pRun.GetScriptInstance()
	pScript.SetFleeFromGroup("player")
	pScript.SetSpeed(1)
	# Done creating PlainAI Run
	#########################################
	#########################################
	# Creating ConditionalAI Wait at (118, 247)
	## Conditions:
	#### Condition TimePassed
	pTimePassed = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 25, 1)
	## Evaluation function:
	def EvalFunc(bTimePassed):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bTimePassed:
			return DONE
		return ACTIVE
	## The ConditionalAI:
	pWait = App.ConditionalAI_Create(pShip, "Wait")
	pWait.SetInterruptable(1)
	pWait.SetContainedAI(pRun)
	pWait.AddCondition(pTimePassed)
	pWait.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI Wait
	#########################################
	#########################################
	# Creating PlainAI WarpOut at (241, 250)
	pWarpOut = App.PlainAI_Create(pShip, "WarpOut")
	pWarpOut.SetScriptModule("Warp")
	pWarpOut.SetInterruptable(1)
	# Done creating PlainAI WarpOut
	#########################################
	#########################################
	# Creating SequenceAI WaitthenRun at (73, 191)
	pWaitthenRun = App.SequenceAI_Create(pShip, "WaitthenRun")
	pWaitthenRun.SetInterruptable(1)
	pWaitthenRun.SetLoopCount(1)
	pWaitthenRun.SetResetIfInterrupted(1)
	pWaitthenRun.SetDoubleCheckAllDone(0)
	pWaitthenRun.SetSkipDormant(0)
	# SeqBlock is at (194, 198)
	pWaitthenRun.AddAI(pWait)
	pWaitthenRun.AddAI(pWarpOut)
	# Done creating SequenceAI WaitthenRun
	#########################################
	#########################################
	# Creating ConditionalAI InPlayerSet at (76, 141)
	## Conditions:
	#### Condition SameSet
	pSameSet = App.ConditionScript_Create("Conditions.ConditionAllInSameSet", "ConditionAllInSameSet", pShip.GetName(), "player")
	## Evaluation function:
	def EvalFunc(bSameSet):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bSameSet:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pInPlayerSet = App.ConditionalAI_Create(pShip, "InPlayerSet")
	pInPlayerSet.SetInterruptable(1)
	pInPlayerSet.SetContainedAI(pWaitthenRun)
	pInPlayerSet.AddCondition(pSameSet)
	pInPlayerSet.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI InPlayerSet
	#########################################
	#########################################
	# Creating PlainAI Stay at (370, 141)
	pStay = App.PlainAI_Create(pShip, "Stay")
	pStay.SetScriptModule("Stay")
	pStay.SetInterruptable(1)
	# Done creating PlainAI Stay
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (191, 26)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (241, 78)
	pPriorityList.AddAI(pInPlayerSet, 1)
	pPriorityList.AddAI(pStay, 2)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (61, 46)
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
	return pAvoidObstacles
