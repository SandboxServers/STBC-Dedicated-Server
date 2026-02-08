import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI WarpToTezle2 at (6, 363)
	pWarpToTezle2 = App.PlainAI_Create(pShip, "WarpToTezle2")
	pWarpToTezle2.SetScriptModule("Warp")
	pWarpToTezle2.SetInterruptable(1)
	pScript = pWarpToTezle2.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.Tezle.Tezle2")
	pScript.SetDestinationPlacementName("FedEnter")
	pScript.SetWarpDuration(1)
	pScript.WarpBlindly(1)
	# Done creating PlainAI WarpToTezle2
	#########################################
	#########################################
	# Creating CompoundAI BasicAttack4Galor3 at (9, 6)
	import AI.Compound.BasicAttack
	pBasicAttack4Galor3 = AI.Compound.BasicAttack.CreateAI(pShip, "Galor 3", SmartTorpSelection = 0)
	# Done creating CompoundAI BasicAttack4Galor3
	#########################################
	#########################################
	# Creating ConditionalAI Galor3AttackKhit at (6, 59)
	## Conditions:
	#### Condition AttackedByGalor3
	pAttackedByGalor3 = App.ConditionScript_Create("Conditions.ConditionAttackedBy", "ConditionAttackedBy", "Khitomer", "Galor 3", 0.20, 0, 120)
	## Evaluation function:
	def EvalFunc(bAttackedByGalor3):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bAttackedByGalor3):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pGalor3AttackKhit = App.ConditionalAI_Create(pShip, "Galor3AttackKhit")
	pGalor3AttackKhit.SetInterruptable(1)
	pGalor3AttackKhit.SetContainedAI(pBasicAttack4Galor3)
	pGalor3AttackKhit.AddCondition(pAttackedByGalor3)
	pGalor3AttackKhit.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI Galor3AttackKhit
	#########################################
	#########################################
	# Creating CompoundAI BasicAttack4Galor4 at (101, 6)
	import AI.Compound.BasicAttack
	pBasicAttack4Galor4 = AI.Compound.BasicAttack.CreateAI(pShip, "Galor 4", SmartTorpSelection = 0)
	# Done creating CompoundAI BasicAttack4Galor4
	#########################################
	#########################################
	# Creating ConditionalAI Galor4AttackKhit at (96, 59)
	## Conditions:
	#### Condition AttackedByGalor4
	pAttackedByGalor4 = App.ConditionScript_Create("Conditions.ConditionAttackedBy", "ConditionAttackedBy", "Khitomer", "Galor 4", 0.20, 0, 120)
	## Evaluation function:
	def EvalFunc(bAttackedByGalor4):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bAttackedByGalor4):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pGalor4AttackKhit = App.ConditionalAI_Create(pShip, "Galor4AttackKhit")
	pGalor4AttackKhit.SetInterruptable(1)
	pGalor4AttackKhit.SetContainedAI(pBasicAttack4Galor4)
	pGalor4AttackKhit.AddCondition(pAttackedByGalor4)
	pGalor4AttackKhit.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI Galor4AttackKhit
	#########################################
	#########################################
	# Creating CompoundAI BasicAttack4Galor1 at (192, 5)
	import AI.Compound.BasicAttack
	pBasicAttack4Galor1 = AI.Compound.BasicAttack.CreateAI(pShip, "Galor 1", SmartTorpSelection = 0)
	# Done creating CompoundAI BasicAttack4Galor1
	#########################################
	#########################################
	# Creating ConditionalAI Galor1AttackKhit at (185, 61)
	## Conditions:
	#### Condition AttackedByGalor1
	pAttackedByGalor1 = App.ConditionScript_Create("Conditions.ConditionAttackedBy", "ConditionAttackedBy", "Khitomer", "Galor 1", 0.20, 0, 120)
	## Evaluation function:
	def EvalFunc(bAttackedByGalor1):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bAttackedByGalor1):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pGalor1AttackKhit = App.ConditionalAI_Create(pShip, "Galor1AttackKhit")
	pGalor1AttackKhit.SetInterruptable(1)
	pGalor1AttackKhit.SetContainedAI(pBasicAttack4Galor1)
	pGalor1AttackKhit.AddCondition(pAttackedByGalor1)
	pGalor1AttackKhit.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI Galor1AttackKhit
	#########################################
	#########################################
	# Creating CompoundAI BasicAttack4Galor2 at (280, 3)
	import AI.Compound.BasicAttack
	pBasicAttack4Galor2 = AI.Compound.BasicAttack.CreateAI(pShip, "Galor 2", SmartTorpSelection = 0)
	# Done creating CompoundAI BasicAttack4Galor2
	#########################################
	#########################################
	# Creating ConditionalAI Galor2AttackKhit at (275, 61)
	## Conditions:
	#### Condition AttackedByGalor2
	pAttackedByGalor2 = App.ConditionScript_Create("Conditions.ConditionAttackedBy", "ConditionAttackedBy", "Khitomer", "Galor 2", 0.20, 0, 120)
	## Evaluation function:
	def EvalFunc(bAttackedByGalor2):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bAttackedByGalor2):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pGalor2AttackKhit = App.ConditionalAI_Create(pShip, "Galor2AttackKhit")
	pGalor2AttackKhit.SetInterruptable(1)
	pGalor2AttackKhit.SetContainedAI(pBasicAttack4Galor2)
	pGalor2AttackKhit.AddCondition(pAttackedByGalor2)
	pGalor2AttackKhit.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI Galor2AttackKhit
	#########################################
	#########################################
	# Creating CompoundAI BasicAttack4FedTezle2Targets at (244, 135)
	import AI.Compound.BasicAttack
	pBasicAttack4FedTezle2Targets = AI.Compound.BasicAttack.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode6.E6M5.E6M5", "g_pFedTezle2Targets"), SmartTorpSelection = 0)
	# Done creating CompoundAI BasicAttack4FedTezle2Targets
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (62, 198)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (134, 143)
	pPriorityList.AddAI(pGalor3AttackKhit, 1)
	pPriorityList.AddAI(pGalor4AttackKhit, 2)
	pPriorityList.AddAI(pGalor1AttackKhit, 3)
	pPriorityList.AddAI(pGalor2AttackKhit, 4)
	pPriorityList.AddAI(pBasicAttack4FedTezle2Targets, 5)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating ConditionalAI EnemiesInSet at (61, 253)
	## Conditions:
	#### Condition CardsInSet
	pCardsInSet = App.ConditionScript_Create("Conditions.ConditionAnyInSameSet", "ConditionAnyInSameSet", pShip.GetName(), "Galor 1", "Galor 2", "Galor 3", "Galor 4", "Keldon 1")
	## Evaluation function:
	def EvalFunc(bCardsInSet):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bCardsInSet:
			return ACTIVE
		return DONE
	## The ConditionalAI:
	pEnemiesInSet = App.ConditionalAI_Create(pShip, "EnemiesInSet")
	pEnemiesInSet.SetInterruptable(1)
	pEnemiesInSet.SetContainedAI(pPriorityList)
	pEnemiesInSet.AddCondition(pCardsInSet)
	pEnemiesInSet.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI EnemiesInSet
	#########################################
	#########################################
	# Creating PlainAI WarpToTezle1 at (206, 300)
	pWarpToTezle1 = App.PlainAI_Create(pShip, "WarpToTezle1")
	pWarpToTezle1.SetScriptModule("Warp")
	pWarpToTezle1.SetInterruptable(1)
	pScript = pWarpToTezle1.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.Tezle.Tezle1")
	pScript.SetDestinationPlacementName("FedEnter")
	pScript.SetWarpDuration(10)
	# Done creating PlainAI WarpToTezle1
	#########################################
	#########################################
	# Creating ConditionalAI WarpTimer at (203, 350)
	## Conditions:
	#### Condition Timer
	pTimer = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 20)
	## Evaluation function:
	def EvalFunc(bTimer):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bTimer):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pWarpTimer = App.ConditionalAI_Create(pShip, "WarpTimer")
	pWarpTimer.SetInterruptable(1)
	pWarpTimer.SetContainedAI(pWarpToTezle1)
	pWarpTimer.AddCondition(pTimer)
	pWarpTimer.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI WarpTimer
	#########################################
	#########################################
	# Creating PlainAI WarpToStarbase at (298, 197)
	pWarpToStarbase = App.PlainAI_Create(pShip, "WarpToStarbase")
	pWarpToStarbase.SetScriptModule("Warp")
	pWarpToStarbase.SetInterruptable(1)
	pScript = pWarpToStarbase.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.Starbase12.Starbase12")
	pScript.SetDestinationPlacementName("FedStart")
	pScript.SetWarpDuration(10)
	# Done creating PlainAI WarpToStarbase
	#########################################
	#########################################
	# Creating ConditionalAI TimerToWarp at (300, 248)
	## Conditions:
	#### Condition Timer
	pTimer = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 15)
	## Evaluation function:
	def EvalFunc(bTimer):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bTimer):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pTimerToWarp = App.ConditionalAI_Create(pShip, "TimerToWarp")
	pTimerToWarp.SetInterruptable(1)
	pTimerToWarp.SetContainedAI(pWarpToStarbase)
	pTimerToWarp.AddCondition(pTimer)
	pTimerToWarp.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI TimerToWarp
	#########################################
	#########################################
	# Creating ConditionalAI KhitDestroyed at (299, 297)
	## Conditions:
	#### Condition ShipDestroyed
	pShipDestroyed = App.ConditionScript_Create("Conditions.ConditionDestroyed", "ConditionDestroyed", "Khitomer")
	## Evaluation function:
	def EvalFunc(bShipDestroyed):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bShipDestroyed):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pKhitDestroyed = App.ConditionalAI_Create(pShip, "KhitDestroyed")
	pKhitDestroyed.SetInterruptable(1)
	pKhitDestroyed.SetContainedAI(pTimerToWarp)
	pKhitDestroyed.AddCondition(pShipDestroyed)
	pKhitDestroyed.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI KhitDestroyed
	#########################################
	#########################################
	# Creating CompoundAI BasicAttack3FedCardTargets at (393, 196)
	import AI.Compound.BasicAttack
	pBasicAttack3FedCardTargets = AI.Compound.BasicAttack.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode6.E6M5.E6M5", "g_pFedCardTargets"), SmartTorpSelection = 0)
	# Done creating CompoundAI BasicAttack3FedCardTargets
	#########################################
	#########################################
	# Creating CompoundAI BasicAttack3Kessok at (413, 247)
	import AI.Compound.BasicAttack
	pBasicAttack3Kessok = AI.Compound.BasicAttack.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode6.E6M5.E6M5", "g_pFedKessokTargets"), SmartTorpSelection = 0)
	# Done creating CompoundAI BasicAttack3Kessok
	#########################################
	#########################################
	# Creating PlainAI FollowKhit at (430, 299)
	pFollowKhit = App.PlainAI_Create(pShip, "FollowKhit")
	pFollowKhit.SetScriptModule("FollowObject")
	pFollowKhit.SetInterruptable(1)
	pScript = pFollowKhit.GetScriptInstance()
	pScript.SetFollowObjectName("Khitomer")
	pScript.SetRoughDistances(35, 45, 55)
	# Done creating PlainAI FollowKhit
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList_2 at (232, 436)
	pPriorityList_2 = App.PriorityListAI_Create(pShip, "PriorityList_2")
	pPriorityList_2.SetInterruptable(1)
	# SeqBlock is at (338, 370)
	pPriorityList_2.AddAI(pKhitDestroyed, 1)
	pPriorityList_2.AddAI(pBasicAttack3FedCardTargets, 2)
	pPriorityList_2.AddAI(pBasicAttack3Kessok, 3)
	pPriorityList_2.AddAI(pFollowKhit, 4)
	# Done creating PriorityListAI PriorityList_2
	#########################################
	#########################################
	# Creating SequenceAI MainSequence at (19, 442)
	pMainSequence = App.SequenceAI_Create(pShip, "MainSequence")
	pMainSequence.SetInterruptable(1)
	pMainSequence.SetLoopCount(1)
	pMainSequence.SetResetIfInterrupted(0)
	pMainSequence.SetDoubleCheckAllDone(0)
	pMainSequence.SetSkipDormant(0)
	# SeqBlock is at (120, 448)
	pMainSequence.AddAI(pWarpToTezle2)
	pMainSequence.AddAI(pEnemiesInSet)
	pMainSequence.AddAI(pWarpTimer)
	pMainSequence.AddAI(pPriorityList_2)
	# Done creating SequenceAI MainSequence
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (15, 486)
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
