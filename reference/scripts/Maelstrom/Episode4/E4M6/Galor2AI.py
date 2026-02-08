import App

def CreateAI(pShip, sShipName):

	#########################################
	# Creating CompoundAI AttackTarget at (103, 272)
	import AI.Compound.BasicAttack
	pAttackTarget = AI.Compound.BasicAttack.CreateAI(pShip, sShipName, Difficulty = 0.1, InaccurateTorps = 1)
	# Done creating CompoundAI AttackTarget
	#########################################
	#########################################
	# Creating CompoundAI AttackPlayer at (199, 271)
	import AI.Compound.BasicAttack
	pAttackPlayer = AI.Compound.BasicAttack.CreateAI(pShip, "player")
	# Done creating CompoundAI AttackPlayer
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (150, 191)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (171, 221)
	pPriorityList.AddAI(pAttackTarget, 1)
	pPriorityList.AddAI(pAttackPlayer, 2)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating ConditionalAI Delay15 at (148, 141)
	## Conditions:
	#### Condition TimerElapsed
	pTimerElapsed = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 15)
	## Evaluation function:
	def EvalFunc(bTimerElapsed):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if(bTimerElapsed):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pDelay15 = App.ConditionalAI_Create(pShip, "Delay15")
	pDelay15.SetInterruptable(1)
	pDelay15.SetContainedAI(pPriorityList)
	pDelay15.AddCondition(pTimerElapsed)
	pDelay15.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI Delay15
	#########################################
	#########################################
	# Creating PreprocessingAI RedAlert at (145, 87)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AlertLevel(App.ShipClass.RED_ALERT)
	## The PreprocessingAI:
	pRedAlert = App.PreprocessingAI_Create(pShip, "RedAlert")
	pRedAlert.SetInterruptable(1)
	pRedAlert.SetPreprocessingMethod(pScript, "Update")
	pRedAlert.SetContainedAI(pDelay15)
	# Done creating PreprocessingAI RedAlert
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (144, 37)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pRedAlert)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
