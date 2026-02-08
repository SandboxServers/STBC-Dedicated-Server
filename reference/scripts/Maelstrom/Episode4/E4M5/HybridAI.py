import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI Scripted at (164, 196)
	pScripted = App.PlainAI_Create(pShip, "Scripted")
	pScripted.SetScriptModule("Flee")
	pScripted.SetInterruptable(1)
	pScript = pScripted.GetScriptInstance()
	pScript.SetFleeFromGroup("player", "USS Enterprise")
	pScript.SetSpeed(1)
	# Done creating PlainAI Scripted
	#########################################
	#########################################
	# Creating ConditionalAI Wait at (165, 156)
	## Conditions:
	#### Condition TimePassed
	pTimePassed = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 10, 1)
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
	pWait.SetContainedAI(pScripted)
	pWait.AddCondition(pTimePassed)
	pWait.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI Wait
	#########################################
	#########################################
	# Creating PlainAI WarpOut at (331, 157)
	pWarpOut = App.PlainAI_Create(pShip, "WarpOut")
	pWarpOut.SetScriptModule("Warp")
	pWarpOut.SetInterruptable(1)
	# Done creating PlainAI WarpOut
	#########################################
	#########################################
	# Creating SequenceAI HybridFlee at (245, 80)
	pHybridFlee = App.SequenceAI_Create(pShip, "HybridFlee")
	pHybridFlee.SetInterruptable(1)
	pHybridFlee.SetLoopCount(1)
	pHybridFlee.SetResetIfInterrupted(1)
	pHybridFlee.SetDoubleCheckAllDone(0)
	pHybridFlee.SetSkipDormant(0)
	# SeqBlock is at (271, 109)
	pHybridFlee.AddAI(pWait)
	pHybridFlee.AddAI(pWarpOut)
	# Done creating SequenceAI HybridFlee
	#########################################
	return pHybridFlee
