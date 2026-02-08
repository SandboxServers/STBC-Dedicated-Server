import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI AttackedScript at (130, 200)
	pAttackedScript = App.PlainAI_Create(pShip, "AttackedScript")
	pAttackedScript.SetScriptModule("RunScript")
	pAttackedScript.SetInterruptable(1)
	pScript = pAttackedScript.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode3.E3M4.E3M4")
	pScript.SetFunction("ShouldIgnoreAttack")
	# Done creating PlainAI AttackedScript
	#########################################
	#########################################
	# Creating PlainAI WarpNowhere at (229, 281)
	pWarpNowhere = App.PlainAI_Create(pShip, "WarpNowhere")
	pWarpNowhere.SetScriptModule("Warp")
	pWarpNowhere.SetInterruptable(1)
	# Done creating PlainAI WarpNowhere
	#########################################
	#########################################
	# Creating ConditionalAI IfDamaged_2 at (228, 243)
	## Conditions:
	#### Condition HullLow
	pHullLow = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName (),App.CT_HULL_SUBSYSTEM,.5)
	#### Condition PowerSystemLow
	pPowerSystemLow = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName (), App.CT_POWER_SUBSYSTEM, .5)
	#### Condition WarpSystemDamaged
	pWarpSystemDamaged = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName (), App.CT_WARP_ENGINE_SUBSYSTEM, .5)
	## Evaluation function:
	def EvalFunc(bHullLow, bPowerSystemLow, bWarpSystemDamaged):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bHullLow or bPowerSystemLow or bWarpSystemDamaged):
			return ACTIVE
		else:
			return DORMANT
	## The ConditionalAI:
	pIfDamaged_2 = App.ConditionalAI_Create(pShip, "IfDamaged_2")
	pIfDamaged_2.SetInterruptable(1)
	pIfDamaged_2.SetContainedAI(pWarpNowhere)
	pIfDamaged_2.AddCondition(pHullLow)
	pIfDamaged_2.AddCondition(pPowerSystemLow)
	pIfDamaged_2.AddCondition(pWarpSystemDamaged)
	pIfDamaged_2.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI IfDamaged_2
	#########################################
	#########################################
	# Creating CompoundAI AttackPlayer at (318, 244)
	import AI.Compound.BasicAttack
	pAttackPlayer = AI.Compound.BasicAttack.CreateAI(pShip, "player", Difficulty = 0.3, SmartShields = 0, WarpOutBeforeDying = 1)
	# Done creating CompoundAI AttackPlayer
	#########################################
	#########################################
	# Creating CompoundAI AttackNagus at (406, 243)
	import AI.Compound.BasicAttack
	pAttackNagus = AI.Compound.BasicAttack.CreateAI(pShip, "Krayvis", Difficulty = 0.34, SmartShields = 0, WarpOutBeforeDying = 1)
	# Done creating CompoundAI AttackNagus
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (227, 167)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (239, 207)
	pPriorityList.AddAI(pIfDamaged_2, 1)
	pPriorityList.AddAI(pAttackPlayer, 2)
	pPriorityList.AddAI(pAttackNagus, 3)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating SequenceAI Sequence at (130, 136)
	pSequence = App.SequenceAI_Create(pShip, "Sequence")
	pSequence.SetInterruptable(1)
	pSequence.SetLoopCount(1)
	pSequence.SetResetIfInterrupted(1)
	pSequence.SetDoubleCheckAllDone(0)
	pSequence.SetSkipDormant(0)
	# SeqBlock is at (158, 176)
	pSequence.AddAI(pAttackedScript)
	pSequence.AddAI(pPriorityList)
	# Done creating SequenceAI Sequence
	#########################################
	#########################################
	# Creating ConditionalAI IfAttackedPlayer at (129, 97)
	## Conditions:
	#### Condition AttackedPlayer
	pAttackedPlayer = App.ConditionScript_Create("Conditions.ConditionAttacked", "ConditionAttacked", "player",  0.0, 0.0, 0.0)
	## Evaluation function:
	def EvalFunc(bAttackedPlayer):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bAttackedPlayer):
			return ACTIVE
		else:
			return DORMANT
	## The ConditionalAI:
	pIfAttackedPlayer = App.ConditionalAI_Create(pShip, "IfAttackedPlayer")
	pIfAttackedPlayer.SetInterruptable(1)
	pIfAttackedPlayer.SetContainedAI(pSequence)
	pIfAttackedPlayer.AddCondition(pAttackedPlayer)
	pIfAttackedPlayer.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI IfAttackedPlayer
	#########################################
	#########################################
	# Creating CompoundAI AttackPlayer_2 at (217, 97)
	import AI.Compound.BasicAttack
	pAttackPlayer_2 = AI.Compound.BasicAttack.CreateAI(pShip, "player", Difficulty = 0.5, ChooseSubsystemTargets = 0, SmartShields = 0, WarpOutBeforeDying = 1)
	# Done creating CompoundAI AttackPlayer_2
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList_2 at (129, 25)
	pPriorityList_2 = App.PriorityListAI_Create(pShip, "PriorityList_2")
	pPriorityList_2.SetInterruptable(1)
	# SeqBlock is at (153, 65)
	pPriorityList_2.AddAI(pIfAttackedPlayer, 1)
	pPriorityList_2.AddAI(pAttackPlayer_2, 2)
	# Done creating PriorityListAI PriorityList_2
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (40, 26)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pPriorityList_2)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
