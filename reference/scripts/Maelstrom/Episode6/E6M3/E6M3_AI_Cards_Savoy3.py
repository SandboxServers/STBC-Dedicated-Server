import App
def CreateAI(pShip, sPlacementName):
	#########################################
	# Creating PlainAI WarpToSavoy1 at (80, 64)
	pWarpToSavoy1 = App.PlainAI_Create(pShip, "WarpToSavoy1")
	pWarpToSavoy1.SetScriptModule("Warp")
	pWarpToSavoy1.SetInterruptable(1)
	pScript = pWarpToSavoy1.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.Savoy.Savoy1")
	pScript.SetDestinationPlacementName(sPlacementName)
	pScript.SetWarpDuration(15)
	# Done creating PlainAI WarpToSavoy1
	#########################################
	#########################################
	# Creating CompoundAI BasicAttackPlayer_2 at (334, 3)
	import AI.Compound.BasicAttack
	pBasicAttackPlayer_2 = AI.Compound.BasicAttack.CreateAI(pShip, "player", Easy_Difficulty = 0.2, Easy_FollowToSB12 = 0, Difficulty = 0.52, FollowToSB12 = 0, Hard_Difficulty = 0.82, Hard_FollowToSB12 = 0)
	# Done creating CompoundAI BasicAttackPlayer_2
	#########################################
	#########################################
	# Creating CompoundAI BasicAttackAllTargets_2 at (426, 87)
	import AI.Compound.BasicAttack
	pBasicAttackAllTargets_2 = AI.Compound.BasicAttack.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode6.E6M3.E6M3", "g_pSavoy3GalorTargets"))
	# Done creating CompoundAI BasicAttackAllTargets_2
	#########################################
	#########################################
	# Creating PriorityListAI TargetPriority at (223, 93)
	pTargetPriority = App.PriorityListAI_Create(pShip, "TargetPriority")
	pTargetPriority.SetInterruptable(1)
	# SeqBlock is at (332, 97)
	pTargetPriority.AddAI(pBasicAttackPlayer_2, 1)
	pTargetPriority.AddAI(pBasicAttackAllTargets_2, 2)
	# Done creating PriorityListAI TargetPriority
	#########################################
	#########################################
	# Creating SequenceAI Savoy1Sequence at (73, 141)
	pSavoy1Sequence = App.SequenceAI_Create(pShip, "Savoy1Sequence")
	pSavoy1Sequence.SetInterruptable(1)
	pSavoy1Sequence.SetLoopCount(1)
	pSavoy1Sequence.SetResetIfInterrupted(1)
	pSavoy1Sequence.SetDoubleCheckAllDone(0)
	pSavoy1Sequence.SetSkipDormant(0)
	# SeqBlock is at (179, 148)
	pSavoy1Sequence.AddAI(pWarpToSavoy1)
	pSavoy1Sequence.AddAI(pTargetPriority)
	# Done creating SequenceAI Savoy1Sequence
	#########################################
	#########################################
	# Creating ConditionalAI HullTakingDamage at (76, 194)
	## Conditions:
	#### Condition HullAt90
	pHullAt90 = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName(), App.CT_HULL_SUBSYSTEM, 0.90)
	## Evaluation function:
	def EvalFunc(bHullAt90):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bHullAt90:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pHullTakingDamage = App.ConditionalAI_Create(pShip, "HullTakingDamage")
	pHullTakingDamage.SetInterruptable(1)
	pHullTakingDamage.SetContainedAI(pSavoy1Sequence)
	pHullTakingDamage.AddCondition(pHullAt90)
	pHullTakingDamage.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI HullTakingDamage
	#########################################
	#########################################
	# Creating ConditionalAI ShipInSavoy3 at (75, 253)
	## Conditions:
	#### Condition InSavoy3
	pInSavoy3 = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", pShip.GetName(), "Savoy3")
	## Evaluation function:
	def EvalFunc(bInSavoy3):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bInSavoy3):
			return ACTIVE
		return DONE
	## The ConditionalAI:
	pShipInSavoy3 = App.ConditionalAI_Create(pShip, "ShipInSavoy3")
	pShipInSavoy3.SetInterruptable(1)
	pShipInSavoy3.SetContainedAI(pHullTakingDamage)
	pShipInSavoy3.AddCondition(pInSavoy3)
	pShipInSavoy3.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI ShipInSavoy3
	#########################################
	#########################################
	# Creating CompoundAI BasicAttackPlayer at (333, 154)
	import AI.Compound.BasicAttack
	pBasicAttackPlayer = AI.Compound.BasicAttack.CreateAI(pShip, "player", Easy_Difficulty = 0.21, Easy_FollowToSB12 = 0, Difficulty = 0.49, FollowToSB12 = 0, Hard_Difficulty = 0.84, Hard_FollowToSB12 = 0)
	# Done creating CompoundAI BasicAttackPlayer
	#########################################
	#########################################
	# Creating PriorityListAI TargetPrioritySavoy3 at (221, 209)
	pTargetPrioritySavoy3 = App.PriorityListAI_Create(pShip, "TargetPrioritySavoy3")
	pTargetPrioritySavoy3.SetInterruptable(1)
	# SeqBlock is at (341, 219)
	pTargetPrioritySavoy3.AddAI(pBasicAttackPlayer, 1)
	# Done creating PriorityListAI TargetPrioritySavoy3
	#########################################
	#########################################
	# Creating ConditionalAI FedsInSavoy at (209, 274)
	## Conditions:
	#### Condition KhitInSavoy3
	pKhitInSavoy3 = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", "Khitomer", "Savoy3")
	#### Condition PlayerInSavoy3
	pPlayerInSavoy3 = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", "player", "Savoy3")
	## Evaluation function:
	def EvalFunc(bKhitInSavoy3, bPlayerInSavoy3):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bKhitInSavoy3) and (bPlayerInSavoy3):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pFedsInSavoy = App.ConditionalAI_Create(pShip, "FedsInSavoy")
	pFedsInSavoy.SetInterruptable(1)
	pFedsInSavoy.SetContainedAI(pTargetPrioritySavoy3)
	pFedsInSavoy.AddCondition(pKhitInSavoy3)
	pFedsInSavoy.AddCondition(pPlayerInSavoy3)
	pFedsInSavoy.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI FedsInSavoy
	#########################################
	#########################################
	# Creating CompoundAI BasicAttackAllTargets at (282, 318)
	import AI.Compound.BasicAttack
	pBasicAttackAllTargets = AI.Compound.BasicAttack.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode6.E6M3.E6M3", "g_pSavoy3GalorTargets"), Easy_Difficulty = 0.16, Easy_FollowToSB12 = 0, FollowToSB12 = 0, SmartShields = 1, Hard_Difficulty = 1.0, Hard_FollowToSB12 = 0)
	# Done creating CompoundAI BasicAttackAllTargets
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (83, 313)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (193, 324)
	pPriorityList.AddAI(pShipInSavoy3, 1)
	pPriorityList.AddAI(pFedsInSavoy, 2)
	pPriorityList.AddAI(pBasicAttackAllTargets, 3)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (16, 348)
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
