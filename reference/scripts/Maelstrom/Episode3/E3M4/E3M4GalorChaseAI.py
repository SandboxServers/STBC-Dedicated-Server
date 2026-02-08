import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI WarpNowhere at (125, 141)
	pWarpNowhere = App.PlainAI_Create(pShip, "WarpNowhere")
	pWarpNowhere.SetScriptModule("Warp")
	pWarpNowhere.SetInterruptable(1)
	# Done creating PlainAI WarpNowhere
	#########################################
	#########################################
	# Creating ConditionalAI IfDamaged_2 at (125, 102)
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
	# Creating PlainAI AttackingUs at (216, 202)
	pAttackingUs = App.PlainAI_Create(pShip, "AttackingUs")
	pAttackingUs.SetScriptModule("RunScript")
	pAttackingUs.SetInterruptable(1)
	pScript = pAttackingUs.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode3.E3M4.E3M4")
	pScript.SetFunction("AttackingUs")
	# Done creating PlainAI AttackingUs
	#########################################
	#########################################
	# Creating CompoundAI AttackPlayer at (309, 264)
	import AI.Compound.BasicAttack
	pAttackPlayer = AI.Compound.BasicAttack.CreateAI(pShip, "player", Difficulty = 0.15, InaccurateTorps = 1)
	# Done creating CompoundAI AttackPlayer
	#########################################
	#########################################
	# Creating CompoundAI AttackNagus at (399, 264)
	import AI.Compound.BasicAttack
	pAttackNagus = AI.Compound.BasicAttack.CreateAI(pShip, "Krayvis", Difficulty = 0.34, SmartShields = 0)
	# Done creating CompoundAI AttackNagus
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList_2 at (308, 201)
	pPriorityList_2 = App.PriorityListAI_Create(pShip, "PriorityList_2")
	pPriorityList_2.SetInterruptable(1)
	# SeqBlock is at (340, 237)
	pPriorityList_2.AddAI(pAttackPlayer, 1)
	pPriorityList_2.AddAI(pAttackNagus, 2)
	# Done creating PriorityListAI PriorityList_2
	#########################################
	#########################################
	# Creating SequenceAI Sequence at (216, 141)
	pSequence = App.SequenceAI_Create(pShip, "Sequence")
	pSequence.SetInterruptable(1)
	pSequence.SetLoopCount(1)
	pSequence.SetResetIfInterrupted(1)
	pSequence.SetDoubleCheckAllDone(0)
	pSequence.SetSkipDormant(0)
	# SeqBlock is at (241, 178)
	pSequence.AddAI(pAttackingUs)
	pSequence.AddAI(pPriorityList_2)
	# Done creating SequenceAI Sequence
	#########################################
	#########################################
	# Creating ConditionalAI IfAttackedByPlayer at (215, 102)
	## Conditions:
	#### Condition AttackedByPlayer
	pAttackedByPlayer = App.ConditionScript_Create("Conditions.ConditionAttackedBy", "ConditionAttackedBy", pShip.GetName(), "player", 0.1, 0.1, 99)
	## Evaluation function:
	def EvalFunc(bAttackedByPlayer):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bAttackedByPlayer):
			return ACTIVE
		else:
			return DORMANT
	## The ConditionalAI:
	pIfAttackedByPlayer = App.ConditionalAI_Create(pShip, "IfAttackedByPlayer")
	pIfAttackedByPlayer.SetInterruptable(1)
	pIfAttackedByPlayer.SetContainedAI(pSequence)
	pIfAttackedByPlayer.AddCondition(pAttackedByPlayer)
	pIfAttackedByPlayer.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI IfAttackedByPlayer
	#########################################
	#########################################
	# Creating CompoundAI Attack at (304, 100)
	import AI.Compound.BasicAttack
	pAttack = AI.Compound.BasicAttack.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode3.E3M4.E3M4", "g_pPartTwoGroup"), Difficulty = 0.34, SmartShields = 0)
	# Done creating CompoundAI Attack
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (126, 26)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (150, 67)
	pPriorityList.AddAI(pIfDamaged_2, 1)
	pPriorityList.AddAI(pIfAttackedByPlayer, 2)
	pPriorityList.AddAI(pAttack, 3)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (38, 26)
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
