import App
def CreateAI(pShip, sPlacementName, pTargetGroup):

	#########################################
	# Creating PlainAI CallWarpOut at (150, 53)
	pCallWarpOut = App.PlainAI_Create(pShip, "CallWarpOut")
	pCallWarpOut.SetScriptModule("RunScript")
	pCallWarpOut.SetInterruptable(1)
	pScript = pCallWarpOut.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode6.E6M5.E6M5")
	pScript.SetFunction("CardsWarpOut")
	# Done creating PlainAI CallWarpOut
	#########################################
	#########################################
	# Creating PlainAI WarpToTezle2 at (265, 15)
	pWarpToTezle2 = App.PlainAI_Create(pShip, "WarpToTezle2")
	pWarpToTezle2.SetScriptModule("Warp")
	pWarpToTezle2.SetInterruptable(1)
	pScript = pWarpToTezle2.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.Tezle.Tezle2")
	pScript.SetDestinationPlacementName(sPlacementName)
	pScript.SetWarpDuration(30)
	# Done creating PlainAI WarpToTezle2
	#########################################
	#########################################
	# Creating CompoundAI BasicAttackCardTargets at (287, 65)
	import AI.Compound.BasicAttack
	pBasicAttackCardTargets = AI.Compound.BasicAttack.CreateAI(pShip, pTargetGroup, Easy_Difficulty = 0.3, Difficulty = 0.76, Hard_Difficulty = 0.95)
	# Done creating CompoundAI BasicAttackCardTargets
	#########################################
	#########################################
	# Creating SequenceAI TezleSequence at (136, 145)
	pTezleSequence = App.SequenceAI_Create(pShip, "TezleSequence")
	pTezleSequence.SetInterruptable(1)
	pTezleSequence.SetLoopCount(1)
	pTezleSequence.SetResetIfInterrupted(1)
	pTezleSequence.SetDoubleCheckAllDone(0)
	pTezleSequence.SetSkipDormant(0)
	# SeqBlock is at (223, 109)
	pTezleSequence.AddAI(pCallWarpOut)
	pTezleSequence.AddAI(pWarpToTezle2)
	pTezleSequence.AddAI(pBasicAttackCardTargets)
	# Done creating SequenceAI TezleSequence
	#########################################
	#########################################
	# Creating ConditionalAI PlayerOrStrikeForceInTezle2 at (128, 210)
	## Conditions:
	#### Condition PlayerInTezle2
	pPlayerInTezle2 = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", "player", "Tezle2")
	#### Condition KhitomerInTezle2
	pKhitomerInTezle2 = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", "Khitomer", "Tezle2")
	## Evaluation function:
	def EvalFunc(bPlayerInTezle2, bKhitomerInTezle2):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bPlayerInTezle2 or bKhitomerInTezle2:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pPlayerOrStrikeForceInTezle2 = App.ConditionalAI_Create(pShip, "PlayerOrStrikeForceInTezle2")
	pPlayerOrStrikeForceInTezle2.SetInterruptable(1)
	pPlayerOrStrikeForceInTezle2.SetContainedAI(pTezleSequence)
	pPlayerOrStrikeForceInTezle2.AddCondition(pPlayerInTezle2)
	pPlayerOrStrikeForceInTezle2.AddCondition(pKhitomerInTezle2)
	pPlayerOrStrikeForceInTezle2.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI PlayerOrStrikeForceInTezle2
	#########################################
	#########################################
	# Creating PlainAI WarpToPrendel5 at (394, 158)
	pWarpToPrendel5 = App.PlainAI_Create(pShip, "WarpToPrendel5")
	pWarpToPrendel5.SetScriptModule("Warp")
	pWarpToPrendel5.SetInterruptable(1)
	pScript = pWarpToPrendel5.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.Prendel.Prendel5")
	pScript.SetDestinationPlacementName(sPlacementName)
	pScript.SetWarpDuration(0)
	# Done creating PlainAI WarpToPrendel5
	#########################################
	#########################################
	# Creating CompoundAI BasicAttackCardTargets_2 at (576, 122)
	import AI.Compound.BasicAttack
	pBasicAttackCardTargets_2 = AI.Compound.BasicAttack.CreateAI(pShip, pTargetGroup, Easy_Difficulty = 0.43, Difficulty = 0.81, Hard_Difficulty = 1.0)
	# Done creating CompoundAI BasicAttackCardTargets_2
	#########################################
	#########################################
	# Creating ConditionalAI PlayerInMySet at (521, 186)
	## Conditions:
	#### Condition PlayerInSameSet
	pPlayerInSameSet = App.ConditionScript_Create("Conditions.ConditionAllInSameSet", "ConditionAllInSameSet", pShip.GetName(), "player")
	## Evaluation function:
	def EvalFunc(bPlayerInSameSet):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bPlayerInSameSet:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pPlayerInMySet = App.ConditionalAI_Create(pShip, "PlayerInMySet")
	pPlayerInMySet.SetInterruptable(1)
	pPlayerInMySet.SetContainedAI(pBasicAttackCardTargets_2)
	pPlayerInMySet.AddCondition(pPlayerInSameSet)
	pPlayerInMySet.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI PlayerInMySet
	#########################################
	#########################################
	# Creating SequenceAI PrendelSequence at (348, 243)
	pPrendelSequence = App.SequenceAI_Create(pShip, "PrendelSequence")
	pPrendelSequence.SetInterruptable(1)
	pPrendelSequence.SetLoopCount(1)
	pPrendelSequence.SetResetIfInterrupted(1)
	pPrendelSequence.SetDoubleCheckAllDone(0)
	pPrendelSequence.SetSkipDormant(1)
	# SeqBlock is at (459, 223)
	pPrendelSequence.AddAI(pWarpToPrendel5)
	pPrendelSequence.AddAI(pPlayerInMySet)
	# Done creating SequenceAI PrendelSequence
	#########################################
	#########################################
	# Creating ConditionalAI PlayerIsInPrendel5 at (241, 270)
	## Conditions:
	#### Condition PlayerInPrendel5
	pPlayerInPrendel5 = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", "player", "Prendel5")
	## Evaluation function:
	def EvalFunc(bPlayerInPrendel5):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bPlayerInPrendel5:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pPlayerIsInPrendel5 = App.ConditionalAI_Create(pShip, "PlayerIsInPrendel5")
	pPlayerIsInPrendel5.SetInterruptable(1)
	pPlayerIsInPrendel5.SetContainedAI(pPrendelSequence)
	pPlayerIsInPrendel5.AddCondition(pPlayerInPrendel5)
	pPlayerIsInPrendel5.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI PlayerIsInPrendel5
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (18, 287)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (125, 278)
	pPriorityList.AddAI(pPlayerOrStrikeForceInTezle2, 1)
	pPriorityList.AddAI(pPlayerIsInPrendel5, 2)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (16, 339)
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
