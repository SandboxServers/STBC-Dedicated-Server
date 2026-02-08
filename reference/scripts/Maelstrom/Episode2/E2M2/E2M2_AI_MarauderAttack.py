import App

def CreateAI(pShip):
	#########################################
	# Creating PlainAI StayBoyStay at (114, 112)
	pStayBoyStay = App.PlainAI_Create(pShip, "StayBoyStay")
	pStayBoyStay.SetScriptModule("Stay")
	pStayBoyStay.SetInterruptable(1)
	# Done creating PlainAI StayBoyStay
	#########################################
	#########################################
	# Creating ConditionalAI GalorsNotClose at (116, 171)
	## Conditions:
	#### Condition GalorsInRange
	pGalorsInRange = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 400, pShip.GetName(), "Galor 1", "Galor 2")
	## Evaluation function:
	def EvalFunc(bGalorsInRange):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bGalorsInRange:
			return DONE
		return ACTIVE
	## The ConditionalAI:
	pGalorsNotClose = App.ConditionalAI_Create(pShip, "GalorsNotClose")
	pGalorsNotClose.SetInterruptable(1)
	pGalorsNotClose.SetContainedAI(pStayBoyStay)
	pGalorsNotClose.AddCondition(pGalorsInRange)
	pGalorsNotClose.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI GalorsNotClose
	#########################################
	#########################################
	# Creating CompoundAI AttackGalors at (162, 218)
	import AI.Compound.BasicAttack
	pAttackGalors = AI.Compound.BasicAttack.CreateAI(pShip, "Galor 1", "Galor 2", Difficulty = 0.2)
	# Done creating CompoundAI AttackGalors
	#########################################
	#########################################
	# Creating SequenceAI Sequence at (15, 262)
	pSequence = App.SequenceAI_Create(pShip, "Sequence")
	pSequence.SetInterruptable(1)
	pSequence.SetLoopCount(1)
	pSequence.SetResetIfInterrupted(1)
	pSequence.SetDoubleCheckAllDone(0)
	pSequence.SetSkipDormant(0)
	# SeqBlock is at (130, 265)
	pSequence.AddAI(pGalorsNotClose)
	pSequence.AddAI(pAttackGalors)
	# Done creating SequenceAI Sequence
	#########################################
	#########################################
	# Creating PreprocessingAI RedAlert at (12, 308)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AlertLevel(App.ShipClass.RED_ALERT)
	## The PreprocessingAI:
	pRedAlert = App.PreprocessingAI_Create(pShip, "RedAlert")
	pRedAlert.SetInterruptable(1)
	pRedAlert.SetPreprocessingMethod(pScript, "Update")
	pRedAlert.SetContainedAI(pSequence)
	# Done creating PreprocessingAI RedAlert
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (13, 355)
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
