import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI Stay at (145, 132)
	pStay = App.PlainAI_Create(pShip, "Stay")
	pStay.SetScriptModule("Stay")
	pStay.SetInterruptable(1)
	# Done creating PlainAI Stay
	#########################################
	#########################################
	# Creating ConditionalAI At_Starbase12 at (145, 99)
	## Conditions:
	#### Condition AtStarbase
	pAtStarbase = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", "player", "Starbase12")
	## Evaluation function:
	def EvalFunc(bAtStarbase):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bAtStarbase:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pAt_Starbase12 = App.ConditionalAI_Create(pShip, "At_Starbase12")
	pAt_Starbase12.SetInterruptable(1)
	pAt_Starbase12.SetContainedAI(pStay)
	pAt_Starbase12.AddCondition(pAtStarbase)
	pAt_Starbase12.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI At_Starbase12
	#########################################
	#########################################
	# Creating PlainAI Warp_Riha1 at (231, 187)
	pWarp_Riha1 = App.PlainAI_Create(pShip, "Warp_Riha1")
	pWarp_Riha1.SetScriptModule("Warp")
	pWarp_Riha1.SetInterruptable(1)
	pScript = pWarp_Riha1.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.Riha.Riha1")
	pScript.SetDestinationPlacementName("Player Start")
	pScript.SetWarpDuration(15)
	# Done creating PlainAI Warp_Riha1
	#########################################
	#########################################
	# Creating CompoundAI AttackDevice1 at (231, 220)
	import AI.Compound.BasicAttack
	pAttackDevice1 = AI.Compound.BasicAttack.CreateAI(pShip, "Device 1")
	# Done creating CompoundAI AttackDevice1
	#########################################
	#########################################
	# Creating SequenceAI Sequence at (232, 133)
	pSequence = App.SequenceAI_Create(pShip, "Sequence")
	pSequence.SetInterruptable(1)
	pSequence.SetLoopCount(1)
	pSequence.SetResetIfInterrupted(1)
	pSequence.SetDoubleCheckAllDone(0)
	pSequence.SetSkipDormant(0)
	# SeqBlock is at (233, 166)
	pSequence.AddAI(pWarp_Riha1)
	pSequence.AddAI(pAttackDevice1)
	# Done creating SequenceAI Sequence
	#########################################
	#########################################
	# Creating ConditionalAI At_Riha1 at (232, 99)
	## Conditions:
	#### Condition Riha1
	pRiha1 = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", "player", "Riha1")
	## Evaluation function:
	def EvalFunc(bRiha1):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bRiha1:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pAt_Riha1 = App.ConditionalAI_Create(pShip, "At_Riha1")
	pAt_Riha1.SetInterruptable(1)
	pAt_Riha1.SetContainedAI(pSequence)
	pAt_Riha1.AddCondition(pRiha1)
	pAt_Riha1.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI At_Riha1
	#########################################
	#########################################
	# Creating PlainAI Warp_Cebalrai1 at (328, 187)
	pWarp_Cebalrai1 = App.PlainAI_Create(pShip, "Warp_Cebalrai1")
	pWarp_Cebalrai1.SetScriptModule("Warp")
	pWarp_Cebalrai1.SetInterruptable(1)
	pScript = pWarp_Cebalrai1.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.Cebalrai.Cebalrai1")
	pScript.SetDestinationPlacementName("Player Start")
	pScript.SetWarpDuration(15)
	# Done creating PlainAI Warp_Cebalrai1
	#########################################
	#########################################
	# Creating CompoundAI AttackDevice2 at (327, 221)
	import AI.Compound.BasicAttack
	pAttackDevice2 = AI.Compound.BasicAttack.CreateAI(pShip, "Device 2")
	# Done creating CompoundAI AttackDevice2
	#########################################
	#########################################
	# Creating SequenceAI Sequence_2 at (330, 132)
	pSequence_2 = App.SequenceAI_Create(pShip, "Sequence_2")
	pSequence_2.SetInterruptable(1)
	pSequence_2.SetLoopCount(1)
	pSequence_2.SetResetIfInterrupted(1)
	pSequence_2.SetDoubleCheckAllDone(0)
	pSequence_2.SetSkipDormant(0)
	# SeqBlock is at (330, 166)
	pSequence_2.AddAI(pWarp_Cebalrai1)
	pSequence_2.AddAI(pAttackDevice2)
	# Done creating SequenceAI Sequence_2
	#########################################
	#########################################
	# Creating ConditionalAI At_Cebalrai1 at (331, 99)
	## Conditions:
	#### Condition Cebalrai1
	pCebalrai1 = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", "player", "Cebalrai")
	## Evaluation function:
	def EvalFunc(bCebalrai1):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bCebalrai1:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pAt_Cebalrai1 = App.ConditionalAI_Create(pShip, "At_Cebalrai1")
	pAt_Cebalrai1.SetInterruptable(1)
	pAt_Cebalrai1.SetContainedAI(pSequence_2)
	pAt_Cebalrai1.AddCondition(pCebalrai1)
	pAt_Cebalrai1.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI At_Cebalrai1
	#########################################
	#########################################
	# Creating PlainAI Warp_Belaruz1 at (437, 187)
	pWarp_Belaruz1 = App.PlainAI_Create(pShip, "Warp_Belaruz1")
	pWarp_Belaruz1.SetScriptModule("Warp")
	pWarp_Belaruz1.SetInterruptable(1)
	pScript = pWarp_Belaruz1.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.Belaruz.Belaruz1")
	pScript.SetDestinationPlacementName("Player Start")
	pScript.SetWarpDuration(15)
	# Done creating PlainAI Warp_Belaruz1
	#########################################
	#########################################
	# Creating CompoundAI AttackDevice3 at (437, 221)
	import AI.Compound.BasicAttack
	pAttackDevice3 = AI.Compound.BasicAttack.CreateAI(pShip, "Device 3")
	# Done creating CompoundAI AttackDevice3
	#########################################
	#########################################
	# Creating SequenceAI Sequence_3 at (436, 132)
	pSequence_3 = App.SequenceAI_Create(pShip, "Sequence_3")
	pSequence_3.SetInterruptable(1)
	pSequence_3.SetLoopCount(1)
	pSequence_3.SetResetIfInterrupted(1)
	pSequence_3.SetDoubleCheckAllDone(0)
	pSequence_3.SetSkipDormant(0)
	# SeqBlock is at (436, 166)
	pSequence_3.AddAI(pWarp_Belaruz1)
	pSequence_3.AddAI(pAttackDevice3)
	# Done creating SequenceAI Sequence_3
	#########################################
	#########################################
	# Creating ConditionalAI At_Belaruz1 at (435, 99)
	## Conditions:
	#### Condition Belaruz1
	pBelaruz1 = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", "player", "Belaruz1")
	## Evaluation function:
	def EvalFunc(bBelaruz1):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bBelaruz1:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pAt_Belaruz1 = App.ConditionalAI_Create(pShip, "At_Belaruz1")
	pAt_Belaruz1.SetInterruptable(1)
	pAt_Belaruz1.SetContainedAI(pSequence_3)
	pAt_Belaruz1.AddCondition(pBelaruz1)
	pAt_Belaruz1.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI At_Belaruz1
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (113, 16)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (262, 29)
	pPriorityList.AddAI(pAt_Starbase12, 1)
	pPriorityList.AddAI(pAt_Riha1, 2)
	pPriorityList.AddAI(pAt_Cebalrai1, 3)
	pPriorityList.AddAI(pAt_Belaruz1, 4)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (27, 46)
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
