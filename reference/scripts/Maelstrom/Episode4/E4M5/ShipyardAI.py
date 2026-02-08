import App
def CreateAI(pShip):
	#########################################
	# Creating CompoundAI StarbaseAttack at (158, 144)
	import AI.Compound.StarbaseAttack
	pStarbaseAttack = AI.Compound.StarbaseAttack.CreateAI(pShip, "player", "USS Enterprise")
	# Done creating CompoundAI StarbaseAttack
	#########################################
	#########################################
	# Creating ConditionalAI Delay at (160, 95)
	## Conditions:
	#### Condition TimerElapsed
	pTimerElapsed = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 90)
	## Evaluation function:
	def EvalFunc(bTimerElapsed):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if(bTimerElapsed):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pDelay = App.ConditionalAI_Create(pShip, "Delay")
	pDelay.SetInterruptable(1)
	pDelay.SetContainedAI(pStarbaseAttack)
	pDelay.AddCondition(pTimerElapsed)
	pDelay.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI Delay
	#########################################
	#########################################
	# Creating PreprocessingAI RedAlert at (157, 37)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AlertLevel(App.ShipClass.RED_ALERT)
	## The PreprocessingAI:
	pRedAlert = App.PreprocessingAI_Create(pShip, "RedAlert")
	pRedAlert.SetInterruptable(1)
	pRedAlert.SetPreprocessingMethod(pScript, "Update")
	pRedAlert.SetContainedAI(pDelay)
	# Done creating PreprocessingAI RedAlert
	#########################################
	return pRedAlert
