import App

def CreateAI(pShip):
	#########################################
	# Creating PlainAI FlyAround at (104, 188)
	pFlyAround = App.PlainAI_Create(pShip, "FlyAround")
	pFlyAround.SetScriptModule("Flee")
	pFlyAround.SetInterruptable(1)
	pScript = pFlyAround.GetScriptInstance()
	pScript.SetFleeFromGroup("player", "RanKuf", "Trayor")
	pScript.SetSpeed(fSpeedFraction = 1.0)
	# Done creating PlainAI FlyAround
	#########################################
	#########################################
	# Creating ConditionalAI AnotherShortTimer_2 at (105, 240)
	## Conditions:
	#### Condition TimerC
	pTimerC = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 15)
	## Evaluation function:
	def EvalFunc(bTimerC):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bTimerC:
			return DONE
		return ACTIVE
	## The ConditionalAI:
	pAnotherShortTimer_2 = App.ConditionalAI_Create(pShip, "AnotherShortTimer_2")
	pAnotherShortTimer_2.SetInterruptable(1)
	pAnotherShortTimer_2.SetContainedAI(pFlyAround)
	pAnotherShortTimer_2.AddCondition(pTimerC)
	pAnotherShortTimer_2.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI AnotherShortTimer_2
	#########################################
	#########################################
	# Creating PlainAI WarpOut at (208, 300)
	pWarpOut = App.PlainAI_Create(pShip, "WarpOut")
	pWarpOut.SetScriptModule("Warp")
	pWarpOut.SetInterruptable(1)
	pScript = pWarpOut.GetScriptInstance()
	pScript.WarpBlindlyNoCollisionsIfImpulseDisabled(bWarpBlindly = 1)
	# Done creating PlainAI WarpOut
	#########################################
	#########################################
	# Creating SequenceAI WarpOutSequence at (34, 300)
	pWarpOutSequence = App.SequenceAI_Create(pShip, "WarpOutSequence")
	pWarpOutSequence.SetInterruptable(1)
	pWarpOutSequence.SetLoopCount(1)
	pWarpOutSequence.SetResetIfInterrupted(1)
	pWarpOutSequence.SetDoubleCheckAllDone(0)
	pWarpOutSequence.SetSkipDormant(0)
	# SeqBlock is at (133, 307)
	pWarpOutSequence.AddAI(pAnotherShortTimer_2)
	pWarpOutSequence.AddAI(pWarpOut)
	# Done creating SequenceAI WarpOutSequence
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (33, 355)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pWarpOutSequence)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
