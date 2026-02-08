import App

def CreateAI(pShip):

	#########################################
	# Creating PlainAI Intercept at (434, 94)
	pIntercept = App.PlainAI_Create(pShip, "Intercept")
	pIntercept.SetScriptModule("Intercept")
	pIntercept.SetInterruptable(1)
	pScript = pIntercept.GetScriptInstance()
	pScript.SetTargetObjectName("player")
	# Done creating PlainAI Intercept
	#########################################
	#########################################
	# Creating ConditionalAI Wait at (344, 114)
	## Conditions:
	#### Condition TimePassed
	pTimePassed = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 20, 1)
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
	pWait.SetContainedAI(pIntercept)
	pWait.AddCondition(pTimePassed)
	pWait.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI Wait
	#########################################
	#########################################
	# Creating CompoundAI Attack at (360, 59)
	import AI.Compound.BasicAttack
	pAttack = AI.Compound.BasicAttack.CreateAI(pShip, "player", "USS Geronimo", "USS San Francisco", Difficulty = 0.9, UseCloaking = 1)
	# Done creating CompoundAI Attack
	#########################################
	#########################################
	# Creating SequenceAI InterceptThenAttack at (244, 25)
	pInterceptThenAttack = App.SequenceAI_Create(pShip, "InterceptThenAttack")
	pInterceptThenAttack.SetInterruptable(1)
	pInterceptThenAttack.SetLoopCount(1)
	pInterceptThenAttack.SetResetIfInterrupted(1)
	pInterceptThenAttack.SetDoubleCheckAllDone(0)
	pInterceptThenAttack.SetSkipDormant(0)
	# SeqBlock is at (335, 32)
	pInterceptThenAttack.AddAI(pWait)
	pInterceptThenAttack.AddAI(pAttack)
	# Done creating SequenceAI InterceptThenAttack
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (156, 45)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pInterceptThenAttack)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
