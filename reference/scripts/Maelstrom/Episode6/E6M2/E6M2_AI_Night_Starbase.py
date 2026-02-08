import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI WarpToStarbase12 at (98, 53)
	pWarpToStarbase12 = App.PlainAI_Create(pShip, "WarpToStarbase12")
	pWarpToStarbase12.SetScriptModule("Warp")
	pWarpToStarbase12.SetInterruptable(1)
	pScript = pWarpToStarbase12.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.Starbase12.Starbase12")
	pScript.SetDestinationPlacementName("NightEnter")
	# Done creating PlainAI WarpToStarbase12
	#########################################
	#########################################
	# Creating ConditionalAI WarpTimer at (98, 130)
	## Conditions:
	#### Condition Timer
	pTimer = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 10)
	## Evaluation function:
	def EvalFunc(bTimer):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bTimer):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pWarpTimer = App.ConditionalAI_Create(pShip, "WarpTimer")
	pWarpTimer.SetInterruptable(1)
	pWarpTimer.SetContainedAI(pWarpToStarbase12)
	pWarpTimer.AddCondition(pTimer)
	pWarpTimer.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI WarpTimer
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (54, 215)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pWarpTimer)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
