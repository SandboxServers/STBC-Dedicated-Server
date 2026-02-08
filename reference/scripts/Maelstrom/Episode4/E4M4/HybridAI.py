import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI RunFromPlayer at (156, 294)
	pRunFromPlayer = App.PlainAI_Create(pShip, "RunFromPlayer")
	pRunFromPlayer.SetScriptModule("Flee")
	pRunFromPlayer.SetInterruptable(1)
	pScript = pRunFromPlayer.GetScriptInstance()
	pScript.SetFleeFromGroup("player")
	pScript.SetSpeed(0.5)
	# Done creating PlainAI RunFromPlayer
	#########################################
	#########################################
	# Creating ConditionalAI Delay at (156, 244)
	## Conditions:
	#### Condition TimerElapsed
	pTimerElapsed = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 70)
	#### Condition FiredUpon
	pFiredUpon = App.ConditionScript_Create("Conditions.ConditionAttackedBy", "ConditionAttackedBy", pShip.GetName (), "player", 1.0, 1.0, 120.0)
	## Evaluation function:
	def EvalFunc(bTimerElapsed, bFiredUpon):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bTimerElapsed or bFiredUpon:
			return DONE
		else:
			return ACTIVE
	## The ConditionalAI:
	pDelay = App.ConditionalAI_Create(pShip, "Delay")
	pDelay.SetInterruptable(1)
	pDelay.SetContainedAI(pRunFromPlayer)
	pDelay.AddCondition(pTimerElapsed)
	pDelay.AddCondition(pFiredUpon)
	pDelay.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI Delay
	#########################################
	#########################################
	# Creating PlainAI ScriptWarpOut at (255, 246)
	pScriptWarpOut = App.PlainAI_Create(pShip, "ScriptWarpOut")
	pScriptWarpOut.SetScriptModule("RunScript")
	pScriptWarpOut.SetInterruptable(1)
	pScript = pScriptWarpOut.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode4.E4M4.E4M4")
	pScript.SetFunction("HybridWarpOut")
	# Done creating PlainAI ScriptWarpOut
	#########################################
	#########################################
	# Creating SequenceAI FleeThenRun at (200, 147)
	pFleeThenRun = App.SequenceAI_Create(pShip, "FleeThenRun")
	pFleeThenRun.SetInterruptable(1)
	pFleeThenRun.SetLoopCount(1)
	pFleeThenRun.SetResetIfInterrupted(1)
	pFleeThenRun.SetDoubleCheckAllDone(0)
	pFleeThenRun.SetSkipDormant(0)
	# SeqBlock is at (226, 177)
	pFleeThenRun.AddAI(pDelay)
	pFleeThenRun.AddAI(pScriptWarpOut)
	# Done creating SequenceAI FleeThenRun
	#########################################
	return pFleeThenRun
	#########################################
	# Creating PreprocessingAI Red_Alert at (200, 105)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AlertLevel(App.ShipClass.RED_ALERT)
	## The PreprocessingAI:
	pRed_Alert = App.PreprocessingAI_Create(pShip, "Red_Alert")
	pRed_Alert.SetInterruptable(1)
	pRed_Alert.SetPreprocessingMethod(pScript, "Update")
	# Done creating PreprocessingAI Red_Alert
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (198, 55)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pRed_Alert)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
