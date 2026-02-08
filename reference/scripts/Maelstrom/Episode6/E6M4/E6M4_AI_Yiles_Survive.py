import App
def CreateAI(pShip, sPlacementName, pTargetGroup):


	#########################################
	# Creating PlainAI WarpToTezle1 at (169, 131)
	pWarpToTezle1 = App.PlainAI_Create(pShip, "WarpToTezle1")
	pWarpToTezle1.SetScriptModule("Warp")
	pWarpToTezle1.SetInterruptable(1)
	pScript = pWarpToTezle1.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.Tezle.Tezle1")
	pScript.SetDestinationPlacementName(sPlacementName)
	pScript.SetWarpDuration(30)
	# Done creating PlainAI WarpToTezle1
	#########################################
	#########################################
	# Creating CompoundAI BasicAttack at (318, 71)
	import AI.Compound.BasicAttack
	pBasicAttack = AI.Compound.BasicAttack.CreateAI(pShip, pTargetGroup, Easy_Difficulty = 0.48, Difficulty = 1.0, Hard_Difficulty = 1.0)
	# Done creating CompoundAI BasicAttack
	#########################################
	#########################################
	# Creating ConditionalAI InPlayersSet at (287, 143)
	## Conditions:
	#### Condition PlayerIsInSet
	pPlayerIsInSet = App.ConditionScript_Create("Conditions.ConditionAllInSameSet", "ConditionAllInSameSet", pShip.GetName(), "player")
	## Evaluation function:
	def EvalFunc(bPlayerIsInSet):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bPlayerIsInSet):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pInPlayersSet = App.ConditionalAI_Create(pShip, "InPlayersSet")
	pInPlayersSet.SetInterruptable(1)
	pInPlayersSet.SetContainedAI(pBasicAttack)
	pInPlayersSet.AddCondition(pPlayerIsInSet)
	pInPlayersSet.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI InPlayersSet
	#########################################
	#########################################
	# Creating SequenceAI MainSequence at (115, 265)
	pMainSequence = App.SequenceAI_Create(pShip, "MainSequence")
	pMainSequence.SetInterruptable(1)
	pMainSequence.SetLoopCount(1)
	pMainSequence.SetResetIfInterrupted(1)
	pMainSequence.SetDoubleCheckAllDone(0)
	pMainSequence.SetSkipDormant(0)
	# SeqBlock is at (255, 228)
	pMainSequence.AddAI(pWarpToTezle1)
	pMainSequence.AddAI(pInPlayersSet)
	# Done creating SequenceAI MainSequence
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (80, 325)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pMainSequence)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
