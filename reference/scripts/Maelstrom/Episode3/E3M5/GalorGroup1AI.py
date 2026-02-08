import App
def CreateAI(pShip, sPlacementName):





	#########################################
	# Creating PlainAI WarpToB2 at (27, 238)
	pWarpToB2 = App.PlainAI_Create(pShip, "WarpToB2")
	pWarpToB2.SetScriptModule("Warp")
	pWarpToB2.SetInterruptable(1)
	pScript = pWarpToB2.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.Belaruz.Belaruz2")
	pScript.SetDestinationPlacementName(sPlacementName)
	pScript.SetWarpDuration(5)
	# Done creating PlainAI WarpToB2
	#########################################
	#########################################
	# Creating ConditionalAI IfDamagedOrMatanLeft at (27, 197)
	## Conditions:
	#### Condition HullLow
	pHullLow = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName (),App.CT_HULL_SUBSYSTEM,.55)
	#### Condition PowerLow
	pPowerLow = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName (), App.CT_POWER_SUBSYSTEM, .55)
	#### Condition WarpDamaged
	pWarpDamaged = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName (), App.CT_WARP_ENGINE_SUBSYSTEM, .55)
	#### Condition ImpulseDamaged
	pImpulseDamaged = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName (), App.CT_IMPULSE_ENGINE_SUBSYSTEM, .55)
	#### Condition MatanHere
	pMatanHere = App.ConditionScript_Create("Conditions.ConditionAllInSameSet", "ConditionAllInSameSet", "MatanShip")
	## Evaluation function:
	def EvalFunc(bHullLow, bPowerLow, bWarpDamaged, bImpulseDamaged, bMatanHere):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bHullLow or bPowerLow or bWarpDamaged or bImpulseDamaged or not bMatanHere):
			return ACTIVE
		else:
			return DORMANT
	## The ConditionalAI:
	pIfDamagedOrMatanLeft = App.ConditionalAI_Create(pShip, "IfDamagedOrMatanLeft")
	pIfDamagedOrMatanLeft.SetInterruptable(1)
	pIfDamagedOrMatanLeft.SetContainedAI(pWarpToB2)
	pIfDamagedOrMatanLeft.AddCondition(pHullLow)
	pIfDamagedOrMatanLeft.AddCondition(pPowerLow)
	pIfDamagedOrMatanLeft.AddCondition(pWarpDamaged)
	pIfDamagedOrMatanLeft.AddCondition(pImpulseDamaged)
	pIfDamagedOrMatanLeft.AddCondition(pMatanHere)
	pIfDamagedOrMatanLeft.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI IfDamagedOrMatanLeft
	#########################################
	#########################################
	# Creating CompoundAI Attack_Kahless_Ro at (121, 273)
	import AI.Compound.BasicAttack
	pAttack_Kahless_Ro = AI.Compound.BasicAttack.CreateAI(pShip, "Kahless Ro", Difficulty = 1.0)
	# Done creating CompoundAI Attack_Kahless_Ro
	#########################################
	#########################################
	# Creating CompoundAI Attack_FriendlyShips at (122, 311)
	import AI.Compound.BasicAttack
	pAttack_FriendlyShips = AI.Compound.BasicAttack.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode3.E3M5.E3M5", "g_pFriendlies"), Difficulty = 0.2)
	# Done creating CompoundAI Attack_FriendlyShips
	#########################################
	#########################################
	# Creating PriorityListAI AttackKlingons at (119, 197)
	pAttackKlingons = App.PriorityListAI_Create(pShip, "AttackKlingons")
	pAttackKlingons.SetInterruptable(1)
	# SeqBlock is at (138, 237)
	pAttackKlingons.AddAI(pAttack_Kahless_Ro, 1)
	pAttackKlingons.AddAI(pAttack_FriendlyShips, 2)
	# Done creating PriorityListAI AttackKlingons
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList_3 at (25, 121)
	pPriorityList_3 = App.PriorityListAI_Create(pShip, "PriorityList_3")
	pPriorityList_3.SetInterruptable(1)
	# SeqBlock is at (51, 161)
	pPriorityList_3.AddAI(pIfDamagedOrMatanLeft, 1)
	pPriorityList_3.AddAI(pAttackKlingons, 2)
	# Done creating PriorityListAI PriorityList_3
	#########################################
	#########################################
	# Creating ConditionalAI IfInBelaruz4 at (25, 83)
	## Conditions:
	#### Condition InBelaruz4
	pInBelaruz4 = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", pShip.GetName (), "Belaruz4")
	## Evaluation function:
	def EvalFunc(bInBelaruz4):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bInBelaruz4):
			return ACTIVE
		else:
			return DONE
	## The ConditionalAI:
	pIfInBelaruz4 = App.ConditionalAI_Create(pShip, "IfInBelaruz4")
	pIfInBelaruz4.SetInterruptable(1)
	pIfInBelaruz4.SetContainedAI(pPriorityList_3)
	pIfInBelaruz4.AddCondition(pInBelaruz4)
	pIfInBelaruz4.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI IfInBelaruz4
	#########################################
	#########################################
	# Creating PlainAI RepairGalor at (230, 181)
	pRepairGalor = App.PlainAI_Create(pShip, "RepairGalor")
	pRepairGalor.SetScriptModule("RunScript")
	pRepairGalor.SetInterruptable(1)
	pScript = pRepairGalor.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode3.E3M5.E3M5")
	pScript.SetFunction("RepairGalor")
	pScript.SetArguments(pShip)
	# Done creating PlainAI RepairGalor
	#########################################
	#########################################
	# Creating PlainAI FleeDialogue at (425, 457)
	pFleeDialogue = App.PlainAI_Create(pShip, "FleeDialogue")
	pFleeDialogue.SetScriptModule("RunScript")
	pFleeDialogue.SetInterruptable(1)
	pScript = pFleeDialogue.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode3.E3M5.E3M5")
	pScript.SetFunction("GalorFlees")
	# Done creating PlainAI FleeDialogue
	#########################################
	#########################################
	# Creating PlainAI RunAway at (524, 419)
	pRunAway = App.PlainAI_Create(pShip, "RunAway")
	pRunAway.SetScriptModule("Flee")
	pRunAway.SetInterruptable(1)
	pScript = pRunAway.GetScriptInstance()
	pScript.SetFleeFromGroup("player")
	# Done creating PlainAI RunAway
	#########################################
	#########################################
	# Creating ConditionalAI Wait at (441, 419)
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
	# Creating PlainAI WarpNowhere at (457, 374)
	pWarpNowhere = App.PlainAI_Create(pShip, "WarpNowhere")
	pWarpNowhere.SetScriptModule("Warp")
	pWarpNowhere.SetInterruptable(1)
	# Done creating PlainAI WarpNowhere
	#########################################
	#########################################
	# Creating SequenceAI FleeSequence at (323, 332)
	pFleeSequence = App.SequenceAI_Create(pShip, "FleeSequence")
	pFleeSequence.SetInterruptable(1)
	pFleeSequence.SetLoopCount(1)
	pFleeSequence.SetResetIfInterrupted(1)
	pFleeSequence.SetDoubleCheckAllDone(0)
	pFleeSequence.SetSkipDormant(0)
	# SeqBlock is at (416, 339)
	pFleeSequence.AddAI(pFleeDialogue)
	pFleeSequence.AddAI(pWait)
	pFleeSequence.AddAI(pWarpNowhere)
	# Done creating SequenceAI FleeSequence
	#########################################
	#########################################
	# Creating ConditionalAI IfDamaged_2 at (322, 293)
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
	pImpulseDamaged = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName (), App.CT_IMPULSE_ENGINE_SUBSYSTEM, .55)
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
	pIfDamaged_2.SetContainedAI(pFleeSequence)
	pIfDamaged_2.AddCondition(pHullLow)
	pIfDamaged_2.AddCondition(pPowerSystemLow)
	pIfDamaged_2.AddCondition(pWarpSystemDamaged)
	pIfDamaged_2.AddCondition(pJonKaDestroyed)
	pIfDamaged_2.AddCondition(pImpulseDamaged)
	pIfDamaged_2.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI IfDamaged_2
	#########################################
	#########################################
	# Creating CompoundAI Attack_Player at (410, 292)
	import AI.Compound.BasicAttack
	pAttack_Player = AI.Compound.BasicAttack.CreateAI(pShip, "player", Difficulty = 0.3, InaccurateTorps = 1, SmartShields = 0)
	# Done creating CompoundAI Attack_Player
	#########################################
	#########################################
	# Creating CompoundAI Attack_Friendlies at (499, 293)
	import AI.Compound.BasicAttack
	pAttack_Friendlies = AI.Compound.BasicAttack.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode3.E3M5.E3M5", "g_pFriendlies"), Difficulty = 0.3, InaccurateTorps = 1, SmartShields = 0)
	# Done creating CompoundAI Attack_Friendlies
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList_2 at (322, 221)
	pPriorityList_2 = App.PriorityListAI_Create(pShip, "PriorityList_2")
	pPriorityList_2.SetInterruptable(1)
	# SeqBlock is at (348, 259)
	pPriorityList_2.AddAI(pIfDamaged_2, 1)
	pPriorityList_2.AddAI(pAttack_Player, 2)
	pPriorityList_2.AddAI(pAttack_Friendlies, 3)
	# Done creating PriorityListAI PriorityList_2
	#########################################
	#########################################
	# Creating ConditionalAI IfWait2Seconds at (321, 181)
	## Conditions:
	#### Condition Wait2Seconds
	pWait2Seconds = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 2.0)
	## Evaluation function:
	def EvalFunc(bWait2Seconds):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bWait2Seconds):
			return ACTIVE
		else:
			return DORMANT
	## The ConditionalAI:
	pIfWait2Seconds = App.ConditionalAI_Create(pShip, "IfWait2Seconds")
	pIfWait2Seconds.SetInterruptable(1)
	pIfWait2Seconds.SetContainedAI(pPriorityList_2)
	pIfWait2Seconds.AddCondition(pWait2Seconds)
	pIfWait2Seconds.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI IfWait2Seconds
	#########################################
	#########################################
	# Creating SequenceAI Sequence at (231, 122)
	pSequence = App.SequenceAI_Create(pShip, "Sequence")
	pSequence.SetInterruptable(1)
	pSequence.SetLoopCount(1)
	pSequence.SetResetIfInterrupted(1)
	pSequence.SetDoubleCheckAllDone(0)
	pSequence.SetSkipDormant(0)
	# SeqBlock is at (257, 158)
	pSequence.AddAI(pRepairGalor)
	pSequence.AddAI(pIfWait2Seconds)
	# Done creating SequenceAI Sequence
	#########################################
	#########################################
	# Creating ConditionalAI InBelaruz2withPlayer at (230, 83)
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
	pInBelaruz2withPlayer.SetContainedAI(pSequence)
	pInBelaruz2withPlayer.AddCondition(pInBelaruz2)
	pInBelaruz2withPlayer.AddCondition(pPlayerInSet)
	pInBelaruz2withPlayer.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI InBelaruz2withPlayer
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (133, 14)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (169, 54)
	pPriorityList.AddAI(pIfInBelaruz4, 1)
	pPriorityList.AddAI(pInBelaruz2withPlayer, 2)
	# Done creating PriorityListAI PriorityList
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
	pAvoidObstacles.SetContainedAI(pPriorityList)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
