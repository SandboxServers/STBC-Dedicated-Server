import App
def CreateAI(pShip):
	#########################################
	# Creating CompoundAI AttackColony at (244, 98)
	import Ai.Compound.BasicAttack
	pAttackColony = Ai.Compound.BasicAttack.CreateAI(pShip, "Colony", Difficulty = 1.0)
	# Done creating CompoundAI AttackColony
	#########################################
	#########################################
	# Creating ConditionalAI Delay at (203, 62)
	## Conditions:
	#### Condition TimerElapsed
	pTimerElapsed = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 50)
	## Evaluation function:
	def EvalFunc(bTimerElapsed):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if(bTimerElapsed):
			return DONE
		return ACTIVE
	## The ConditionalAI:
	pDelay = App.ConditionalAI_Create(pShip, "Delay")
	pDelay.SetInterruptable(1)
	pDelay.SetContainedAI(pAttackColony)
	pDelay.AddCondition(pTimerElapsed)
	pDelay.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI Delay
	#########################################
	#########################################
	# Creating CompoundAI AttackAll at (240, 20)
	import Ai.Compound.BasicAttack
	pAttackAll = Ai.Compound.BasicAttack.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode8.E8M2.E8M2", "pFriendlies"), Difficulty = 0.4)
	# Done creating CompoundAI AttackAll
	#########################################
	#########################################
	# Creating SequenceAI AttackSequence at (105, 20)
	pAttackSequence = App.SequenceAI_Create(pShip, "AttackSequence")
	pAttackSequence.SetInterruptable(1)
	pAttackSequence.SetLoopCount(1)
	pAttackSequence.SetResetIfInterrupted(1)
	pAttackSequence.SetDoubleCheckAllDone(0)
	pAttackSequence.SetSkipDormant(0)
	# SeqBlock is at (194, 27)
	pAttackSequence.AddAI(pDelay)
	pAttackSequence.AddAI(pAttackAll)
	# Done creating SequenceAI AttackSequence
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (22, 40)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pAttackSequence)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
