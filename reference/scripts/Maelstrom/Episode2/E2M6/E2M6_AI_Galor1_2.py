import App
def CreateAI(pShip, sPlacementName, pTargetGroup, eGalorsDownEvent):






	#########################################
	# Creating PlainAI WarpToBiranu1 at (22, 60)
	pWarpToBiranu1 = App.PlainAI_Create(pShip, "WarpToBiranu1")
	pWarpToBiranu1.SetScriptModule("Warp")
	pWarpToBiranu1.SetInterruptable(1)
	pScript = pWarpToBiranu1.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.Biranu.Biranu1")
	pScript.SetDestinationPlacementName(sPlacementName)
	pScript.SetWarpDuration(5)
	# Done creating PlainAI WarpToBiranu1
	#########################################
	#########################################
	# Creating ConditionalAI TwoGalorLeft at (18, 117)
	## Conditions:
	#### Condition TwoGalorsDown
	pTwoGalorsDown = App.ConditionScript_Create("Conditions.ConditionMissionEvent", "ConditionMissionEvent", eGalorsDownEvent)
	## Evaluation function:
	def EvalFunc(bTwoGalorsDown):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bTwoGalorsDown:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pTwoGalorLeft = App.ConditionalAI_Create(pShip, "TwoGalorLeft")
	pTwoGalorLeft.SetInterruptable(1)
	pTwoGalorLeft.SetContainedAI(pWarpToBiranu1)
	pTwoGalorLeft.AddCondition(pTwoGalorsDown)
	pTwoGalorLeft.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI TwoGalorLeft
	#########################################
	#########################################
	# Creating CompoundAI BasicAttack4TargetGroup at (157, 62)
	import AI.Compound.BasicAttack
	pBasicAttack4TargetGroup = AI.Compound.BasicAttack.CreateAI(pShip, pTargetGroup, Difficulty = 0.35, ChooseSubsystemTargets = 0)
	# Done creating CompoundAI BasicAttack4TargetGroup
	#########################################
	#########################################
	# Creating ConditionalAI GalorsTakeDamage at (159, 119)
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
	pGalorsTakeDamage.SetContainedAI(pBasicAttack4TargetGroup)
	pGalorsTakeDamage.AddCondition(pGalor1AttackedBOP1)
	pGalorsTakeDamage.AddCondition(pGalor1AttackedBOP2)
	pGalorsTakeDamage.AddCondition(pGalor2AttackedBOP1)
	pGalorsTakeDamage.AddCondition(pGalor2AttackedBOP2)
	pGalorsTakeDamage.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI GalorsTakeDamage
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (16, 197)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (142, 178)
	pPriorityList.AddAI(pTwoGalorLeft, 1)
	pPriorityList.AddAI(pGalorsTakeDamage, 2)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating ConditionalAI InTheBiranu2Set at (18, 248)
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
	pInTheBiranu2Set = App.ConditionalAI_Create(pShip, "InTheBiranu2Set")
	pInTheBiranu2Set.SetInterruptable(1)
	pInTheBiranu2Set.SetContainedAI(pPriorityList)
	pInTheBiranu2Set.AddCondition(pInBiranu2Set)
	pInTheBiranu2Set.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI InTheBiranu2Set
	#########################################
	#########################################
	# Creating CompoundAI BasicAttack at (159, 253)
	import AI.Compound.BasicAttack
	pBasicAttack = AI.Compound.BasicAttack.CreateAI(pShip, pTargetGroup, Difficulty = 0.3, MaxFiringRange = 400.0)
	# Done creating CompoundAI BasicAttack
	#########################################
	#########################################
	# Creating SequenceAI Sequence at (4, 314)
	pSequence = App.SequenceAI_Create(pShip, "Sequence")
	pSequence.SetInterruptable(1)
	pSequence.SetLoopCount(1)
	pSequence.SetResetIfInterrupted(1)
	pSequence.SetDoubleCheckAllDone(0)
	pSequence.SetSkipDormant(0)
	# SeqBlock is at (120, 326)
	pSequence.AddAI(pInTheBiranu2Set)
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
