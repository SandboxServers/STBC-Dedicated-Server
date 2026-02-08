import App
def CreateAI(pShip, pTargetGroup):

	#########################################
	# Creating PlainAI InterceptPlayer at (161, 18)
	pInterceptPlayer = App.PlainAI_Create(pShip, "InterceptPlayer")
	pInterceptPlayer.SetScriptModule("Intercept")
	pInterceptPlayer.SetInterruptable(1)
	pScript = pInterceptPlayer.GetScriptInstance()
	pScript.SetTargetObjectName("player")
	pScript.SetMaximumSpeed(10)
	pScript.SetInterceptDistance(0.1)
	# Done creating PlainAI InterceptPlayer
	#########################################
	#########################################
	# Creating ConditionalAI PlayerNotInRange at (163, 76)
	## Conditions:
	#### Condition PlayerInSet
	pPlayerInSet = App.ConditionScript_Create("Conditions.ConditionAnyInSameSet", "ConditionAnyInSameSet", "player", pShip.GetName())
	#### Condition PlayerInRange
	pPlayerInRange = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 200, "player", pShip.GetName())
	## Evaluation function:
	def EvalFunc(bPlayerInSet, bPlayerInRange):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bPlayerInSet):
			if(bPlayerInRange):
				return DONE
			else: return ACTIVE
		else: return DORMANT
	## The ConditionalAI:
	pPlayerNotInRange = App.ConditionalAI_Create(pShip, "PlayerNotInRange")
	pPlayerNotInRange.SetInterruptable(1)
	pPlayerNotInRange.SetContainedAI(pInterceptPlayer)
	pPlayerNotInRange.AddCondition(pPlayerInSet)
	pPlayerNotInRange.AddCondition(pPlayerInRange)
	pPlayerNotInRange.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI PlayerNotInRange
	#########################################
	#########################################
	# Creating CompoundAI BasicAttackTargets at (271, 103)
	import AI.Compound.BasicAttack
	pBasicAttackTargets = AI.Compound.BasicAttack.CreateAI(pShip, pTargetGroup, Easy_Difficulty = 0.45, Difficulty = 1.0, Hard_Difficulty = 1.0)
	# Done creating CompoundAI BasicAttackTargets
	#########################################
	#########################################
	# Creating SequenceAI MainSequence at (118, 155)
	pMainSequence = App.SequenceAI_Create(pShip, "MainSequence")
	pMainSequence.SetInterruptable(1)
	pMainSequence.SetLoopCount(1)
	pMainSequence.SetResetIfInterrupted(1)
	pMainSequence.SetDoubleCheckAllDone(0)
	pMainSequence.SetSkipDormant(0)
	# SeqBlock is at (224, 147)
	pMainSequence.AddAI(pPlayerNotInRange)
	pMainSequence.AddAI(pBasicAttackTargets)
	# Done creating SequenceAI MainSequence
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (29, 183)
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
