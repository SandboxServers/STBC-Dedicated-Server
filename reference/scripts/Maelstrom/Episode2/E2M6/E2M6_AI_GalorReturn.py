import App

def CreateAI(pShip, pTargetGroup, sPlacementName):

	#########################################
	# Creating CompoundAI BasicAttack at (57, 35)
	import AI.Compound.BasicAttack
	pBasicAttack = AI.Compound.BasicAttack.CreateAI(pShip, pTargetGroup, Easy_Difficulty = 0.2, Easy_MaxFiringRange = 311.0, Difficulty = 0.3, MaxFiringRange = 300.0, SmartShields = 0, Hard_Difficulty = 0.33, Hard_MaxFiringRange = 304.0)
	# Done creating CompoundAI BasicAttack
	#########################################
	#########################################
	# Creating ConditionalAI NoOneInSet at (62, 91)
	## Conditions:
	#### Condition TrayorInSet
	pTrayorInSet = App.ConditionScript_Create("Conditions.ConditionAllInSameSet", "ConditionAllInSameSet", "Trayor", "Biranu1")
	#### Condition PlayerInSet
	pPlayerInSet = App.ConditionScript_Create("Conditions.ConditionAllInSameSet", "ConditionAllInSameSet", "player", "Biranu1")
	#### Condition RanKufInSet
	pRanKufInSet = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", "RanKuf", "Biranu1")
	## Evaluation function:
	def EvalFunc(bTrayorInSet, bPlayerInSet, bRanKufInSet):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bTrayorInSet or bPlayerInSet or bRanKufInSet:
			return ACTIVE
		return DONE
	## The ConditionalAI:
	pNoOneInSet = App.ConditionalAI_Create(pShip, "NoOneInSet")
	pNoOneInSet.SetInterruptable(1)
	pNoOneInSet.SetContainedAI(pBasicAttack)
	pNoOneInSet.AddCondition(pTrayorInSet)
	pNoOneInSet.AddCondition(pPlayerInSet)
	pNoOneInSet.AddCondition(pRanKufInSet)
	pNoOneInSet.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI NoOneInSet
	#########################################
	#########################################
	# Creating PlainAI WarpToBiranu2 at (162, 66)
	pWarpToBiranu2 = App.PlainAI_Create(pShip, "WarpToBiranu2")
	pWarpToBiranu2.SetScriptModule("Warp")
	pWarpToBiranu2.SetInterruptable(1)
	pScript = pWarpToBiranu2.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.Biranu.Biranu2")
	pScript.SetDestinationPlacementName(sPlacementName)
	# Done creating PlainAI WarpToBiranu2
	#########################################
	#########################################
	# Creating CompoundAI BasicAttack_2 at (267, 136)
	import AI.Compound.BasicAttack
	pBasicAttack_2 = AI.Compound.BasicAttack.CreateAI(pShip, pTargetGroup, Easy_Difficulty = 0.22, Easy_MaxFiringRange = 304.0, Difficulty = 0.3, MaxFiringRange = 300.0, SmartShields = 0, Hard_Difficulty = 0.34, Hard_MaxFiringRange = 304.0)
	# Done creating CompoundAI BasicAttack_2
	#########################################
	#########################################
	# Creating SequenceAI Sequence at (30, 165)
	pSequence = App.SequenceAI_Create(pShip, "Sequence")
	pSequence.SetInterruptable(1)
	pSequence.SetLoopCount(1)
	pSequence.SetResetIfInterrupted(1)
	pSequence.SetDoubleCheckAllDone(0)
	pSequence.SetSkipDormant(0)
	# SeqBlock is at (132, 141)
	pSequence.AddAI(pNoOneInSet)
	pSequence.AddAI(pWarpToBiranu2)
	pSequence.AddAI(pBasicAttack_2)
	# Done creating SequenceAI Sequence
	#########################################
	return pSequence
