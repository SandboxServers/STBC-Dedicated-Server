import App
def CreateAI(pShip, sPlacementName, eGalorsDownEvent):




	#########################################
	# Creating PlainAI WarpToBiranu1 at (27, 115)
	pWarpToBiranu1 = App.PlainAI_Create(pShip, "WarpToBiranu1")
	pWarpToBiranu1.SetScriptModule("Warp")
	pWarpToBiranu1.SetInterruptable(1)
	pScript = pWarpToBiranu1.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.Biranu.Biranu1")
	pScript.SetDestinationPlacementName(sPlacementName)
	pScript.SetWarpDuration(10)
	# Done creating PlainAI WarpToBiranu1
	#########################################
	#########################################
	# Creating ConditionalAI TwoGalorLeft at (28, 159)
	## Conditions:
	#### Condition TwoGalorsLeft
	pTwoGalorsLeft = App.ConditionScript_Create("Conditions.ConditionMissionEvent", "ConditionMissionEvent", eGalorsDownEvent)
	## Evaluation function:
	def EvalFunc(bTwoGalorsLeft):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bTwoGalorsLeft:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pTwoGalorLeft = App.ConditionalAI_Create(pShip, "TwoGalorLeft")
	pTwoGalorLeft.SetInterruptable(1)
	pTwoGalorLeft.SetContainedAI(pWarpToBiranu1)
	pTwoGalorLeft.AddCondition(pTwoGalorsLeft)
	pTwoGalorLeft.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI TwoGalorLeft
	#########################################
	#########################################
	# Creating PlainAI Call_GalorAttackingPlayer at (83, 37)
	pCall_GalorAttackingPlayer = App.PlainAI_Create(pShip, "Call_GalorAttackingPlayer")
	pCall_GalorAttackingPlayer.SetScriptModule("RunScript")
	pCall_GalorAttackingPlayer.SetInterruptable(1)
	pScript = pCall_GalorAttackingPlayer.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode2.E2M6.E2M6")
	pScript.SetFunction("GalorAttackingPlayer")
	pScript.SetArguments(None)
	# Done creating PlainAI Call_GalorAttackingPlayer
	#########################################
	#########################################
	# Creating CompoundAI AttackPlayer at (183, 38)
	import AI.Compound.BasicAttack
	pAttackPlayer = AI.Compound.BasicAttack.CreateAI(pShip, "player", Easy_Difficulty = 0.2, Difficulty = 0.2, InaccurateTorps = 0, Hard_Difficulty = 0.5, Hard_MaxFiringRange = 360.0)
	# Done creating CompoundAI AttackPlayer
	#########################################
	#########################################
	# Creating SequenceAI AttackPlayerSequence at (115, 127)
	pAttackPlayerSequence = App.SequenceAI_Create(pShip, "AttackPlayerSequence")
	pAttackPlayerSequence.SetInterruptable(1)
	pAttackPlayerSequence.SetLoopCount(1)
	pAttackPlayerSequence.SetResetIfInterrupted(1)
	pAttackPlayerSequence.SetDoubleCheckAllDone(0)
	pAttackPlayerSequence.SetSkipDormant(0)
	# SeqBlock is at (144, 96)
	pAttackPlayerSequence.AddAI(pCall_GalorAttackingPlayer)
	pAttackPlayerSequence.AddAI(pAttackPlayer)
	# Done creating SequenceAI AttackPlayerSequence
	#########################################
	#########################################
	# Creating ConditionalAI AttackedByPlayer at (114, 183)
	## Conditions:
	#### Condition PlayerAttacks
	pPlayerAttacks = App.ConditionScript_Create("Conditions.ConditionAttackedBy", "ConditionAttackedBy", pShip.GetName(), "player", 0.20, 0.10, 0)
	## Evaluation function:
	def EvalFunc(bPlayerAttacks):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bPlayerAttacks:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pAttackedByPlayer = App.ConditionalAI_Create(pShip, "AttackedByPlayer")
	pAttackedByPlayer.SetInterruptable(1)
	pAttackedByPlayer.SetContainedAI(pAttackPlayerSequence)
	pAttackedByPlayer.AddCondition(pPlayerAttacks)
	pAttackedByPlayer.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI AttackedByPlayer
	#########################################
	#########################################
	# Creating PlainAI Call_CardsAttackStation at (425, 42)
	pCall_CardsAttackStation = App.PlainAI_Create(pShip, "Call_CardsAttackStation")
	pCall_CardsAttackStation.SetScriptModule("RunScript")
	pCall_CardsAttackStation.SetInterruptable(1)
	pScript = pCall_CardsAttackStation.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode2.E2M6.E2M6")
	pScript.SetFunction("CardsAttackStation")
	# Done creating PlainAI Call_CardsAttackStation
	#########################################
	#########################################
	# Creating PlainAI TorpRunStation at (440, 82)
	pTorpRunStation = App.PlainAI_Create(pShip, "TorpRunStation")
	pTorpRunStation.SetScriptModule("TorpedoRun")
	pTorpRunStation.SetInterruptable(1)
	pScript = pTorpRunStation.GetScriptInstance()
	pScript.SetTargetObjectName("Biranu Station")
	# Done creating PlainAI TorpRunStation
	#########################################
	#########################################
	# Creating ConditionalAI ShortTimer at (441, 129)
	## Conditions:
	#### Condition Timer5
	pTimer5 = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 5)
	## Evaluation function:
	def EvalFunc(bTimer5):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bTimer5:
			return DONE
		return ACTIVE
	## The ConditionalAI:
	pShortTimer = App.ConditionalAI_Create(pShip, "ShortTimer")
	pShortTimer.SetInterruptable(1)
	pShortTimer.SetContainedAI(pTorpRunStation)
	pShortTimer.AddCondition(pTimer5)
	pShortTimer.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI ShortTimer
	#########################################
	#########################################
	# Creating CompoundAI BasicAttackStation at (487, 176)
	import AI.Compound.BasicAttack
	pBasicAttackStation = AI.Compound.BasicAttack.CreateAI(pShip, "Biranu Station", Difficulty = 0.5, ChooseSubsystemTargets = 1)
	# Done creating CompoundAI BasicAttackStation
	#########################################
	#########################################
	# Creating SequenceAI AttackStationSequence at (313, 85)
	pAttackStationSequence = App.SequenceAI_Create(pShip, "AttackStationSequence")
	pAttackStationSequence.SetInterruptable(1)
	pAttackStationSequence.SetLoopCount(1)
	pAttackStationSequence.SetResetIfInterrupted(1)
	pAttackStationSequence.SetDoubleCheckAllDone(0)
	pAttackStationSequence.SetSkipDormant(0)
	# SeqBlock is at (416, 183)
	pAttackStationSequence.AddAI(pCall_CardsAttackStation)
	pAttackStationSequence.AddAI(pShortTimer)
	pAttackStationSequence.AddAI(pBasicAttackStation)
	# Done creating SequenceAI AttackStationSequence
	#########################################
	#########################################
	# Creating ConditionalAI AttackTimer at (225, 105)
	## Conditions:
	#### Condition Timer40
	pTimer40 = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 40)
	## Evaluation function:
	def EvalFunc(bTimer40):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bTimer40:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pAttackTimer = App.ConditionalAI_Create(pShip, "AttackTimer")
	pAttackTimer.SetInterruptable(1)
	pAttackTimer.SetContainedAI(pAttackStationSequence)
	pAttackTimer.AddCondition(pTimer40)
	pAttackTimer.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI AttackTimer
	#########################################
	#########################################
	# Creating CompoundAI BasicAttack4BOPs at (232, 151)
	import AI.Compound.BasicAttack
	pBasicAttack4BOPs = AI.Compound.BasicAttack.CreateAI(pShip, "RanKuf", "Trayor", Difficulty = 0.3)
	# Done creating CompoundAI BasicAttack4BOPs
	#########################################
	#########################################
	# Creating ConditionalAI GalorsTakeDamage at (235, 201)
	## Conditions:
	#### Condition Galor1AttackedBOP1
	pGalor1AttackedBOP1 = App.ConditionScript_Create("Conditions.ConditionAttackedBy", "ConditionAttackedBy", "Galor 1", "RanKuf", 0.001, 0.01, 200)
	#### Condition Galor1AttackedBOP2
	pGalor1AttackedBOP2 = App.ConditionScript_Create("Conditions.ConditionAttackedBy", "ConditionAttackedBy", "Galor 1", "Trayor", 0.001, 0.001, 200)
	#### Condition Galor2AttackedBOP1
	pGalor2AttackedBOP1 = App.ConditionScript_Create("Conditions.ConditionAttackedBy", "ConditionAttackedBy", "Galor 2", "RanKuf", 0.001, 0.001, 200)
	#### Condition Galor2AttackedBOP2
	pGalor2AttackedBOP2 = App.ConditionScript_Create("Conditions.ConditionAttackedBy", "ConditionAttackedBy", "Galor 2", "Trayor", 0.001, 0.001, 200)
	## Evaluation function:
	def EvalFunc(bGalor1AttackedBOP1, bGalor1AttackedBOP2, bGalor2AttackedBOP1, bGalor2AttackedBOP2):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bGalor1AttackedBOP1 or bGalor1AttackedBOP2 or bGalor2AttackedBOP1 or bGalor2AttackedBOP2:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pGalorsTakeDamage = App.ConditionalAI_Create(pShip, "GalorsTakeDamage")
	pGalorsTakeDamage.SetInterruptable(1)
	pGalorsTakeDamage.SetContainedAI(pBasicAttack4BOPs)
	pGalorsTakeDamage.AddCondition(pGalor1AttackedBOP1)
	pGalorsTakeDamage.AddCondition(pGalor1AttackedBOP2)
	pGalorsTakeDamage.AddCondition(pGalor2AttackedBOP1)
	pGalorsTakeDamage.AddCondition(pGalor2AttackedBOP2)
	pGalorsTakeDamage.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI GalorsTakeDamage
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (6, 224)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (137, 229)
	pPriorityList.AddAI(pTwoGalorLeft, 1)
	pPriorityList.AddAI(pAttackedByPlayer, 2)
	pPriorityList.AddAI(pAttackTimer, 3)
	pPriorityList.AddAI(pGalorsTakeDamage, 4)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating ConditionalAI InBiranu2 at (4, 268)
	## Conditions:
	#### Condition InBiranu2Set
	pInBiranu2Set = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", pShip.GetName(), "Biranu2")
	## Evaluation function:
	def EvalFunc(bInBiranu2Set):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bInBiranu2Set):
			return ACTIVE
		return DONE
	## The ConditionalAI:
	pInBiranu2 = App.ConditionalAI_Create(pShip, "InBiranu2")
	pInBiranu2.SetInterruptable(1)
	pInBiranu2.SetContainedAI(pPriorityList)
	pInBiranu2.AddCondition(pInBiranu2Set)
	pInBiranu2.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI InBiranu2
	#########################################
	#########################################
	# Creating CompoundAI BasicAttack at (227, 296)
	import AI.Compound.BasicAttack
	pBasicAttack = AI.Compound.BasicAttack.CreateAI(pShip, "RanKuf", "Trayor", "player", Easy_Difficulty = 0.25, Easy_MaxFiringRange = 311.0, Difficulty = 0.3, AvoidTorps = 1, SmartShields = 0)
	# Done creating CompoundAI BasicAttack
	#########################################
	#########################################
	# Creating SequenceAI Sequence at (5, 318)
	pSequence = App.SequenceAI_Create(pShip, "Sequence")
	pSequence.SetInterruptable(1)
	pSequence.SetLoopCount(1)
	pSequence.SetResetIfInterrupted(1)
	pSequence.SetDoubleCheckAllDone(0)
	pSequence.SetSkipDormant(0)
	# SeqBlock is at (163, 304)
	pSequence.AddAI(pInBiranu2)
	pSequence.AddAI(pBasicAttack)
	# Done creating SequenceAI Sequence
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (3, 365)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pSequence)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
