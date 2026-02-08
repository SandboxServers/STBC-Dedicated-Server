import App
def CreateAI(pShip, pTargetGroup):



	#########################################
	# Creating PlainAI InterceptStation at (88, 80)
	pInterceptStation = App.PlainAI_Create(pShip, "InterceptStation")
	pInterceptStation.SetScriptModule("Intercept")
	pInterceptStation.SetInterruptable(1)
	pScript = pInterceptStation.GetScriptInstance()
	pScript.SetTargetObjectName("Biranu Station")
	# Done creating PlainAI InterceptStation
	#########################################
	#########################################
	# Creating PreprocessingAI GreenAlert at (89, 137)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AlertLevel(App.ShipClass.GREEN_ALERT)
	## The PreprocessingAI:
	pGreenAlert = App.PreprocessingAI_Create(pShip, "GreenAlert")
	pGreenAlert.SetInterruptable(1)
	pGreenAlert.SetPreprocessingMethod(pScript, "Update")
	pGreenAlert.SetContainedAI(pInterceptStation)
	# Done creating PreprocessingAI GreenAlert
	#########################################
	#########################################
	# Creating ConditionalAI GettingClose at (89, 184)
	## Conditions:
	#### Condition InRangeOfStation
	pInRangeOfStation = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 500, pShip.GetName(), "Biranu Station")
	## Evaluation function:
	def EvalFunc(bInRangeOfStation):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bInRangeOfStation:
			return DONE
		return ACTIVE
	## The ConditionalAI:
	pGettingClose = App.ConditionalAI_Create(pShip, "GettingClose")
	pGettingClose.SetInterruptable(1)
	pGettingClose.SetContainedAI(pGreenAlert)
	pGettingClose.AddCondition(pInRangeOfStation)
	pGettingClose.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI GettingClose
	#########################################
	#########################################
	# Creating CompoundAI BasicAttackTargets_2 at (219, 135)
	import AI.Compound.BasicAttack
	pBasicAttackTargets_2 = AI.Compound.BasicAttack.CreateAI(pShip, pTargetGroup, Easy_Difficulty = 0.2, Easy_InaccurateTorps = 0, Difficulty = 0.22, MaxFiringRange = 300.0, InaccurateTorps = 0, Hard_Difficulty = 0.6, Hard_MaxFiringRange = 304.0)
	# Done creating CompoundAI BasicAttackTargets_2
	#########################################
	#########################################
	# Creating PreprocessingAI RedAlert at (221, 185)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AlertLevel(App.ShipClass.RED_ALERT)
	## The PreprocessingAI:
	pRedAlert = App.PreprocessingAI_Create(pShip, "RedAlert")
	pRedAlert.SetInterruptable(1)
	pRedAlert.SetPreprocessingMethod(pScript, "Update")
	pRedAlert.SetContainedAI(pBasicAttackTargets_2)
	# Done creating PreprocessingAI RedAlert
	#########################################
	#########################################
	# Creating SequenceAI Sequence at (41, 259)
	pSequence = App.SequenceAI_Create(pShip, "Sequence")
	pSequence.SetInterruptable(1)
	pSequence.SetLoopCount(1)
	pSequence.SetResetIfInterrupted(1)
	pSequence.SetDoubleCheckAllDone(0)
	pSequence.SetSkipDormant(0)
	# SeqBlock is at (159, 246)
	pSequence.AddAI(pGettingClose)
	pSequence.AddAI(pRedAlert)
	# Done creating SequenceAI Sequence
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (42, 320)
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
