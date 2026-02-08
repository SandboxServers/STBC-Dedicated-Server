import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI FleeFromStarbase at (105, 105)
	pFleeFromStarbase = App.PlainAI_Create(pShip, "FleeFromStarbase")
	pFleeFromStarbase.SetScriptModule("Flee")
	pFleeFromStarbase.SetInterruptable(1)
	pScript = pFleeFromStarbase.GetScriptInstance()
	pScript.SetFleeFromGroup("Starbase 12")
	pScript.SetSpeed(0.5)
	# Done creating PlainAI FleeFromStarbase
	#########################################
	#########################################
	# Creating ConditionalAI PlayerNotInSet at (104, 164)
	## Conditions:
	#### Condition PlayerInSet
	pPlayerInSet = App.ConditionScript_Create("Conditions.ConditionAllInSameSet", "ConditionAllInSameSet", pShip.GetName(), "player")
	## Evaluation function:
	def EvalFunc(bPlayerInSet):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bPlayerInSet:
			return DORMANT
		return ACTIVE
	## The ConditionalAI:
	pPlayerNotInSet = App.ConditionalAI_Create(pShip, "PlayerNotInSet")
	pPlayerNotInSet.SetInterruptable(1)
	pPlayerNotInSet.SetContainedAI(pFleeFromStarbase)
	pPlayerNotInSet.AddCondition(pPlayerInSet)
	pPlayerNotInSet.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI PlayerNotInSet
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (105, 219)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pPlayerNotInSet)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
