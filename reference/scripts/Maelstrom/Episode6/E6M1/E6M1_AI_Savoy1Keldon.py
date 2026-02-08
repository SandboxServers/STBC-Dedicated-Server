import App
def CreateAI(pShip, pTargetGroup, sPlacementName):


	#########################################
	# Creating CompoundAI BasicAttack_2 at (125, 179)
	import AI.Compound.BasicAttack
	pBasicAttack_2 = AI.Compound.BasicAttack.CreateAI(pShip, pTargetGroup, Difficulty = 0.51)
	# Done creating CompoundAI BasicAttack_2
	#########################################
	#########################################
	# Creating ConditionalAI WarpOutTimer at (130, 234)
	## Conditions:
	#### Condition Timer
	pTimer = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 1)
	## Evaluation function:
	def EvalFunc(bTimer):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bTimer):
			return DONE
		return ACTIVE
	## The ConditionalAI:
	pWarpOutTimer = App.ConditionalAI_Create(pShip, "WarpOutTimer")
	pWarpOutTimer.SetInterruptable(1)
	pWarpOutTimer.SetContainedAI(pBasicAttack_2)
	pWarpOutTimer.AddCondition(pTimer)
	pWarpOutTimer.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI WarpOutTimer
	#########################################
	#########################################
	# Creating PlainAI WarpToSavoy1 at (235, 217)
	pWarpToSavoy1 = App.PlainAI_Create(pShip, "WarpToSavoy1")
	pWarpToSavoy1.SetScriptModule("Warp")
	pWarpToSavoy1.SetInterruptable(1)
	pScript = pWarpToSavoy1.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.Savoy.Savoy1")
	pScript.SetDestinationPlacementName(sPlacementName)
	pScript.SetWarpDuration(3)
	# Done creating PlainAI WarpToSavoy1
	#########################################
	#########################################
	# Creating CompoundAI BasicAttack at (282, 272)
	import AI.Compound.BasicAttack
	pBasicAttack = AI.Compound.BasicAttack.CreateAI(pShip, pTargetGroup, Easy_Difficulty = 0.32, Difficulty = 0.93, Hard_Difficulty = 1.0)
	# Done creating CompoundAI BasicAttack
	#########################################
	#########################################
	# Creating SequenceAI Sequence at (33, 298)
	pSequence = App.SequenceAI_Create(pShip, "Sequence")
	pSequence.SetInterruptable(1)
	pSequence.SetLoopCount(1)
	pSequence.SetResetIfInterrupted(1)
	pSequence.SetDoubleCheckAllDone(0)
	pSequence.SetSkipDormant(0)
	# SeqBlock is at (190, 305)
	pSequence.AddAI(pWarpOutTimer)
	pSequence.AddAI(pWarpToSavoy1)
	pSequence.AddAI(pBasicAttack)
	# Done creating SequenceAI Sequence
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (37, 349)
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
