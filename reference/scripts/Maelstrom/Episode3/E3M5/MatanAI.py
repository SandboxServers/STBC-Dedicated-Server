import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI MatanDialogue at (7, 333)
	pMatanDialogue = App.PlainAI_Create(pShip, "MatanDialogue")
	pMatanDialogue.SetScriptModule("RunScript")
	pMatanDialogue.SetInterruptable(1)
	pScript = pMatanDialogue.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode3.E3M5.E3M5")
	pScript.SetFunction("MatanGoodbye")
	# Done creating PlainAI MatanDialogue
	#########################################
	#########################################
	# Creating PlainAI RunAway at (103, 368)
	pRunAway = App.PlainAI_Create(pShip, "RunAway")
	pRunAway.SetScriptModule("Flee")
	pRunAway.SetInterruptable(1)
	pScript = pRunAway.GetScriptInstance()
	pScript.SetFleeFromGroup("player")
	# Done creating PlainAI RunAway
	#########################################
	#########################################
	# Creating ConditionalAI Wait at (101, 335)
	## Conditions:
	#### Condition TimePassed
	pTimePassed = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 10, 1)
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
	pWait.SetContainedAI(pRunAway)
	pWait.AddCondition(pTimePassed)
	pWait.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI Wait
	#########################################
	#########################################
	# Creating PlainAI Warp_to_nowhere at (195, 334)
	pWarp_to_nowhere = App.PlainAI_Create(pShip, "Warp_to_nowhere")
	pWarp_to_nowhere.SetScriptModule("Warp")
	pWarp_to_nowhere.SetInterruptable(1)
	# Done creating PlainAI Warp_to_nowhere
	#########################################
	#########################################
	# Creating SequenceAI Sequence at (36, 211)
	pSequence = App.SequenceAI_Create(pShip, "Sequence")
	pSequence.SetInterruptable(1)
	pSequence.SetLoopCount(1)
	pSequence.SetResetIfInterrupted(1)
	pSequence.SetDoubleCheckAllDone(0)
	pSequence.SetSkipDormant(0)
	# SeqBlock is at (50, 250)
	pSequence.AddAI(pMatanDialogue)
	pSequence.AddAI(pWait)
	pSequence.AddAI(pWarp_to_nowhere)
	# Done creating SequenceAI Sequence
	#########################################
	#########################################
	# Creating ConditionalAI IfMatanDamaged at (48, 162)
	## Conditions:
	#### Condition HullLow
	pHullLow = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName(), App.CT_HULL_SUBSYSTEM, .55)
	#### Condition PowerSystemLow
	pPowerSystemLow = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName(), App.CT_POWER_SUBSYSTEM, .55)
	#### Condition JonKaDestroyed
	pJonKaDestroyed = App.ConditionScript_Create("Conditions.ConditionDestroyed", "ConditionDestroyed", "JonKa")
	#### Condition WarpDamaged
	pWarpDamaged = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName(), App.CT_WARP_ENGINE_SUBSYSTEM, .55)
	#### Condition ImpulseDamaged
	pImpulseDamaged = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName(), App.CT_IMPULSE_ENGINE_SUBSYSTEM, .55)
	## Evaluation function:
	def EvalFunc(bHullLow, bPowerSystemLow, bJonKaDestroyed, bWarpDamaged, bImpulseDamaged):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bHullLow or bPowerSystemLow or bWarpDamaged or bImpulseDamaged or bJonKaDestroyed:
			return ACTIVE
		else:
			return DORMANT
	## The ConditionalAI:
	pIfMatanDamaged = App.ConditionalAI_Create(pShip, "IfMatanDamaged")
	pIfMatanDamaged.SetInterruptable(1)
	pIfMatanDamaged.SetContainedAI(pSequence)
	pIfMatanDamaged.AddCondition(pHullLow)
	pIfMatanDamaged.AddCondition(pPowerSystemLow)
	pIfMatanDamaged.AddCondition(pJonKaDestroyed)
	pIfMatanDamaged.AddCondition(pWarpDamaged)
	pIfMatanDamaged.AddCondition(pImpulseDamaged)
	pIfMatanDamaged.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI IfMatanDamaged
	#########################################
	#########################################
	# Creating CompoundAI Attack_Kahless_Ro at (207, 224)
	import AI.Compound.BasicAttack
	pAttack_Kahless_Ro = AI.Compound.BasicAttack.CreateAI(pShip, "Kahless Ro", Difficulty = 1.0)
	# Done creating CompoundAI Attack_Kahless_Ro
	#########################################
	#########################################
	# Creating CompoundAI Attack_Everyone_Else at (298, 224)
	import AI.Compound.BasicAttack
	pAttack_Everyone_Else = AI.Compound.BasicAttack.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode3.E3M5.E3M5", "g_pFriendlies"), Difficulty = 0.2, InaccurateTorps = 1)
	# Done creating CompoundAI Attack_Everyone_Else
	#########################################
	#########################################
	# Creating PriorityListAI AttackKlingons at (213, 154)
	pAttackKlingons = App.PriorityListAI_Create(pShip, "AttackKlingons")
	pAttackKlingons.SetInterruptable(1)
	# SeqBlock is at (230, 187)
	pAttackKlingons.AddAI(pAttack_Kahless_Ro, 1)
	pAttackKlingons.AddAI(pAttack_Everyone_Else, 2)
	# Done creating PriorityListAI AttackKlingons
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (130, 68)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (160, 105)
	pPriorityList.AddAI(pIfMatanDamaged, 1)
	pPriorityList.AddAI(pAttackKlingons, 2)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (127, 26)
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
