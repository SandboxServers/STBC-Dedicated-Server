import App
def CreateAI(pShip, sPlacementName):





	#########################################
	# Creating PlainAI FleeDialogue at (12, 412)
	pFleeDialogue = App.PlainAI_Create(pShip, "FleeDialogue")
	pFleeDialogue.SetScriptModule("RunScript")
	pFleeDialogue.SetInterruptable(1)
	pScript = pFleeDialogue.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode3.E3M5.E3M5")
	pScript.SetFunction("GalorFlees")
	# Done creating PlainAI FleeDialogue
	#########################################
	#########################################
	# Creating PlainAI RunAway at (107, 445)
	pRunAway = App.PlainAI_Create(pShip, "RunAway")
	pRunAway.SetScriptModule("Flee")
	pRunAway.SetInterruptable(1)
	pScript = pRunAway.GetScriptInstance()
	pScript.SetFleeFromGroup("player")
	# Done creating PlainAI RunAway
	#########################################
	#########################################
	# Creating ConditionalAI Wait at (101, 409)
	## Conditions:
	#### Condition TimePassed
	pTimePassed = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 15, 1)
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
	# Creating PlainAI WarpNowhere at (200, 409)
	pWarpNowhere = App.PlainAI_Create(pShip, "WarpNowhere")
	pWarpNowhere.SetScriptModule("Warp")
	pWarpNowhere.SetInterruptable(1)
	# Done creating PlainAI WarpNowhere
	#########################################
	#########################################
	# Creating SequenceAI Sequence at (26, 292)
	pSequence = App.SequenceAI_Create(pShip, "Sequence")
	pSequence.SetInterruptable(1)
	pSequence.SetLoopCount(1)
	pSequence.SetResetIfInterrupted(1)
	pSequence.SetDoubleCheckAllDone(0)
	pSequence.SetSkipDormant(0)
	# SeqBlock is at (40, 328)
	pSequence.AddAI(pFleeDialogue)
	pSequence.AddAI(pWait)
	pSequence.AddAI(pWarpNowhere)
	# Done creating SequenceAI Sequence
	#########################################
	#########################################
	# Creating ConditionalAI IfDamaged_2 at (26, 251)
	## Conditions:
	#### Condition HullLow
	pHullLow = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName (),App.CT_HULL_SUBSYSTEM,.55)
	#### Condition PowerSystemLow
	pPowerSystemLow = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName (), App.CT_POWER_SUBSYSTEM, .55)
	#### Condition WarpSystemDamaged
	pWarpSystemDamaged = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName (), App.CT_WARP_ENGINE_SUBSYSTEM, .55)
	#### Condition JonKaDestroyed
	pJonKaDestroyed = App.ConditionScript_Create("Conditions.ConditionDestroyed", "ConditionDestroyed", "JonKa")
	#### Condition ImpulseDamaged
	pImpulseDamaged = App.ConditionScript_Create("Conditions.ConditionSystemDisabled", "ConditionSystemDisabled", pShip.GetName (), App.CT_IMPULSE_ENGINE_SUBSYSTEM, .55)
	## Evaluation function:
	def EvalFunc(bHullLow, bPowerSystemLow, bWarpSystemDamaged, bJonKaDestroyed, bImpulseDamaged):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bHullLow or bPowerSystemLow or bWarpSystemDamaged or bImpulseDamaged or bJonKaDestroyed):
			return ACTIVE
		else:
			return DORMANT
	## The ConditionalAI:
	pIfDamaged_2 = App.ConditionalAI_Create(pShip, "IfDamaged_2")
	pIfDamaged_2.SetInterruptable(1)
	pIfDamaged_2.SetContainedAI(pSequence)
	pIfDamaged_2.AddCondition(pHullLow)
	pIfDamaged_2.AddCondition(pPowerSystemLow)
	pIfDamaged_2.AddCondition(pWarpSystemDamaged)
	pIfDamaged_2.AddCondition(pJonKaDestroyed)
	pIfDamaged_2.AddCondition(pImpulseDamaged)
	pIfDamaged_2.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI IfDamaged_2
	#########################################
	#########################################
	# Creating CompoundAI Attack_Player at (166, 354)
	import AI.Compound.BasicAttack
	pAttack_Player = AI.Compound.BasicAttack.CreateAI(pShip, "player", Difficulty = 0.3, InaccurateTorps = 1, SmartShields = 0)
	# Done creating CompoundAI Attack_Player
	#########################################
	#########################################
	# Creating CompoundAI Attack_Friendlies_2 at (256, 353)
	import AI.Compound.BasicAttack
	pAttack_Friendlies_2 = AI.Compound.BasicAttack.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode3.E3M5.E3M5", "g_pFriendlies"), Difficulty = 0.25, InaccurateTorps = 1)
	# Done creating CompoundAI Attack_Friendlies_2
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList_3 at (163, 291)
	pPriorityList_3 = App.PriorityListAI_Create(pShip, "PriorityList_3")
	pPriorityList_3.SetInterruptable(1)
	# SeqBlock is at (189, 329)
	pPriorityList_3.AddAI(pAttack_Player, 1)
	pPriorityList_3.AddAI(pAttack_Friendlies_2, 2)
	# Done creating PriorityListAI PriorityList_3
	#########################################
	#########################################
	# Creating ConditionalAI IfAttackedByPlayer at (162, 251)
	## Conditions:
	#### Condition AttackedByPlayer
	pAttackedByPlayer = App.ConditionScript_Create("Conditions.ConditionAttackedBy", "ConditionAttackedBy", pShip.GetName (), "player", 0.5, 0.2, 120.0)
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
	pIfAttackedByPlayer.SetContainedAI(pPriorityList_3)
	pIfAttackedByPlayer.AddCondition(pAttackedByPlayer)
	pIfAttackedByPlayer.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI IfAttackedByPlayer
	#########################################
	#########################################
	# Creating CompoundAI Attack_Friendlies at (367, 250)
	import AI.Compound.BasicAttack
	pAttack_Friendlies = AI.Compound.BasicAttack.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode3.E3M5.E3M5", "g_pFriendlies"), Difficulty = 0.25)
	# Done creating CompoundAI Attack_Friendlies
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList_2 at (33, 134)
	pPriorityList_2 = App.PriorityListAI_Create(pShip, "PriorityList_2")
	pPriorityList_2.SetInterruptable(1)
	# SeqBlock is at (53, 170)
	pPriorityList_2.AddAI(pIfDamaged_2, 1)
	pPriorityList_2.AddAI(pIfAttackedByPlayer, 2)
	pPriorityList_2.AddAI(pAttack_Friendlies, 3)
	# Done creating PriorityListAI PriorityList_2
	#########################################
	#########################################
	# Creating ConditionalAI InBelaruz2withPlayer at (32, 82)
	## Conditions:
	#### Condition InBelaruz2
	pInBelaruz2 = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", pShip.GetName (), "Belaruz2")
	#### Condition PlayerInSet
	pPlayerInSet = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", "player", "Belaruz2")
	## Evaluation function:
	def EvalFunc(bInBelaruz2, bPlayerInSet):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bInBelaruz2 and bPlayerInSet):
			return ACTIVE
		else:
			return DORMANT
	## The ConditionalAI:
	pInBelaruz2withPlayer = App.ConditionalAI_Create(pShip, "InBelaruz2withPlayer")
	pInBelaruz2withPlayer.SetInterruptable(1)
	pInBelaruz2withPlayer.SetContainedAI(pPriorityList_2)
	pInBelaruz2withPlayer.AddCondition(pInBelaruz2)
	pInBelaruz2withPlayer.AddCondition(pPlayerInSet)
	pInBelaruz2withPlayer.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI InBelaruz2withPlayer
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (31, 17)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pInBelaruz2withPlayer)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
