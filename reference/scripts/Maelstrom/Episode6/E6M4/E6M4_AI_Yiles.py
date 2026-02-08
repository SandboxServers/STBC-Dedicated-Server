import App
def CreateAI(pShip, pTargetGroup):

	#########################################
	# Creating PlainAI InterceptPlayer at (66, 120)
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
	# Creating ConditionalAI PlayerNotInRange at (74, 175)
	## Conditions:
	#### Condition PlayerInSet
	pPlayerInSet = App.ConditionScript_Create("Conditions.ConditionAllInSameSet", "ConditionAllInSameSet", "player", "Galor 1", "Keldon 1")
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
			else:
				return ACTIVE
		else:
			return DORMANT
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
	# Creating CompoundAI BasicAttackTargets at (181, 96)
	import AI.Compound.BasicAttack
	pBasicAttackTargets = AI.Compound.BasicAttack.CreateAI(pShip, pTargetGroup, Easy_Difficulty = 0.41, Difficulty = 1.0, Hard_Difficulty = 1.0)
	# Done creating CompoundAI BasicAttackTargets
	#########################################
	#########################################
	# Creating ConditionalAI TwoCardsInSet at (176, 170)
	## Conditions:
	#### Condition TwoCardRemain
	pTwoCardRemain = App.ConditionScript_Create("Conditions.ConditionAllInSameSet", "ConditionAllInSameSet", "Galor 1", "Keldon 1")
	## Evaluation function:
	def EvalFunc(bTwoCardRemain):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bTwoCardRemain):
			return ACTIVE
		else: 
			return DONE
	## The ConditionalAI:
	pTwoCardsInSet = App.ConditionalAI_Create(pShip, "TwoCardsInSet")
	pTwoCardsInSet.SetInterruptable(1)
	pTwoCardsInSet.SetContainedAI(pBasicAttackTargets)
	pTwoCardsInSet.AddCondition(pTwoCardRemain)
	pTwoCardsInSet.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI TwoCardsInSet
	#########################################
	#########################################
	# Creating PlainAI Call_SurvivingCardRetreats at (288, 147)
	pCall_SurvivingCardRetreats = App.PlainAI_Create(pShip, "Call_SurvivingCardRetreats")
	pCall_SurvivingCardRetreats.SetScriptModule("RunScript")
	pCall_SurvivingCardRetreats.SetInterruptable(1)
	pScript = pCall_SurvivingCardRetreats.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode6.E6M4.E6M4")
	pScript.SetFunction("SurvivingCardRetreats")
	# Done creating PlainAI Call_SurvivingCardRetreats
	#########################################
	#########################################
	# Creating PlainAI WarpToYiles1 at (317, 192)
	pWarpToYiles1 = App.PlainAI_Create(pShip, "WarpToYiles1")
	pWarpToYiles1.SetScriptModule("Warp")
	pWarpToYiles1.SetInterruptable(1)
	pScript = pWarpToYiles1.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.Yiles.Yiles1")
	pScript.SetDestinationPlacementName("CardEnter")
	pScript.SetWarpDuration(15)
	# Done creating PlainAI WarpToYiles1
	#########################################
	#########################################
	# Creating CompoundAI BasicAttack2Targets_2 at (422, 191)
	import AI.Compound.BasicAttack
	pBasicAttack2Targets_2 = AI.Compound.BasicAttack.CreateAI(pShip, pTargetGroup, Easy_Difficulty = 0.44, Difficulty = 1.0, Hard_Difficulty = 1.0)
	# Done creating CompoundAI BasicAttack2Targets_2
	#########################################
	#########################################
	# Creating ConditionalAI PlayerArrivesYiles at (373, 250)
	## Conditions:
	#### Condition PlayerInYiles1
	pPlayerInYiles1 = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", "player", "Yiles1")
	## Evaluation function:
	def EvalFunc(bPlayerInYiles1):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bPlayerInYiles1):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pPlayerArrivesYiles = App.ConditionalAI_Create(pShip, "PlayerArrivesYiles")
	pPlayerArrivesYiles.SetInterruptable(1)
	pPlayerArrivesYiles.SetContainedAI(pBasicAttack2Targets_2)
	pPlayerArrivesYiles.AddCondition(pPlayerInYiles1)
	pPlayerArrivesYiles.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI PlayerArrivesYiles
	#########################################
	#########################################
	# Creating SequenceAI EndSequence at (198, 258)
	pEndSequence = App.SequenceAI_Create(pShip, "EndSequence")
	pEndSequence.SetInterruptable(1)
	pEndSequence.SetLoopCount(1)
	pEndSequence.SetResetIfInterrupted(1)
	pEndSequence.SetDoubleCheckAllDone(0)
	pEndSequence.SetSkipDormant(0)
	# SeqBlock is at (298, 265)
	pEndSequence.AddAI(pCall_SurvivingCardRetreats)
	pEndSequence.AddAI(pWarpToYiles1)
	pEndSequence.AddAI(pPlayerArrivesYiles)
	# Done creating SequenceAI EndSequence
	#########################################
	#########################################
	# Creating SequenceAI MainSequence at (23, 252)
	pMainSequence = App.SequenceAI_Create(pShip, "MainSequence")
	pMainSequence.SetInterruptable(1)
	pMainSequence.SetLoopCount(1)
	pMainSequence.SetResetIfInterrupted(1)
	pMainSequence.SetDoubleCheckAllDone(0)
	pMainSequence.SetSkipDormant(0)
	# SeqBlock is at (141, 265)
	pMainSequence.AddAI(pPlayerNotInRange)
	pMainSequence.AddAI(pTwoCardsInSet)
	pMainSequence.AddAI(pEndSequence)
	# Done creating SequenceAI MainSequence
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (18, 306)
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
