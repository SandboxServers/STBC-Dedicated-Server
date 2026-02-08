import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI Run at (463, 248)
	pRun = App.PlainAI_Create(pShip, "Run")
	pRun.SetScriptModule("Flee")
	pRun.SetInterruptable(1)
	pScript = pRun.GetScriptInstance()
	pScript.SetFleeFromGroup("player")
	pScript.SetSpeed(1)
	# Done creating PlainAI Run
	#########################################
	#########################################
	# Creating ConditionalAI Wait at (422, 208)
	## Conditions:
	#### Condition TimePassed
	pTimePassed = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 15, 1)
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
	# Creating PlainAI WarpOut at (456, 160)
	pWarpOut = App.PlainAI_Create(pShip, "WarpOut")
	pWarpOut.SetScriptModule("Warp")
	pWarpOut.SetInterruptable(1)
	pScript = pWarpOut.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.DeepSpace.DeepSpace")
	# Done creating PlainAI WarpOut
	#########################################
	#########################################
	# Creating SequenceAI WaitthenRun at (312, 160)
	pWaitthenRun = App.SequenceAI_Create(pShip, "WaitthenRun")
	pWaitthenRun.SetInterruptable(1)
	pWaitthenRun.SetLoopCount(1)
	pWaitthenRun.SetResetIfInterrupted(1)
	pWaitthenRun.SetDoubleCheckAllDone(0)
	pWaitthenRun.SetSkipDormant(0)
	# SeqBlock is at (413, 167)
	pWaitthenRun.AddAI(pWait)
	pWaitthenRun.AddAI(pWarpOut)
	# Done creating SequenceAI WaitthenRun
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (212, 180)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pWaitthenRun)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
