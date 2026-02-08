import App
def CreateAI(pShip):
	#########################################
	# Creating CompoundAI Attack_Player at (110, 167)
	import AI.Compound.BasicAttack
	pAttack_Player = AI.Compound.BasicAttack.CreateAI(pShip, "player", WarpOutBeforeDying = 1)
	# Flag WarpOutBeforeDying = 1
	# Done creating CompoundAI Attack_Player
	#########################################
	#########################################
	# Creating ConditionalAI Conditional at (111, 127)
	## Conditions:
	#### Condition Attacked
	pAttacked = App.ConditionScript_Create("Conditions.ConditionSingleShieldBelow", "ConditionSingleShieldBelow", "Galor2",  0.05, App.ShieldClass.NUM_SHIELDS)
	## Evaluation function:
	def EvalFunc(bAttacked):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bAttacked:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pConditional = App.ConditionalAI_Create(pShip, "Conditional")
	pConditional.SetInterruptable(1)
	pConditional.SetContainedAI(pAttack_Player)
	pConditional.AddCondition(pAttacked)
	pConditional.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI Conditional
	#########################################
	#########################################
	# Creating CompoundAI Attack_Base at (238, 99)
	import AI.Compound.BasicAttack
	pAttack_Base = AI.Compound.BasicAttack.CreateAI(pShip, "Outpost", ChooseSubsystemTargets = 0, WarpOutBeforeDying = 1)
	# Flag ChooseSubsystemTargets = 0
	# Flag WarpOutBeforeDying = 1
	# Done creating CompoundAI Attack_Base
	#########################################
	#########################################
	# Creating CompoundAI AttackPlayer2 at (329, 100)
	import AI.Compound.BasicAttack
	pAttackPlayer2 = AI.Compound.BasicAttack.CreateAI(pShip, "player", WarpOutBeforeDying = 1)
	# Flag WarpOutBeforeDying = 1
	# Done creating CompoundAI AttackPlayer2
	#########################################
	#########################################
	# Creating SequenceAI Sequence at (195, 50)
	pSequence = App.SequenceAI_Create(pShip, "Sequence")
	pSequence.SetInterruptable(1)
	pSequence.SetLoopCount(1)
	pSequence.SetResetIfInterrupted(1)
	pSequence.SetDoubleCheckAllDone(0)
	pSequence.SetSkipDormant(0)
	# SeqBlock is at (299, 58)
	pSequence.AddAI(pAttack_Base)
	pSequence.AddAI(pAttackPlayer2)
	# Done creating SequenceAI Sequence
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (50, 50)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (157, 57)
	pPriorityList.AddAI(pConditional, 1)
	pPriorityList.AddAI(pSequence, 2)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (50, 15)
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
