import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI WarpToOna3 at (140, 139)
	pWarpToOna3 = App.PlainAI_Create(pShip, "WarpToOna3")
	pWarpToOna3.SetScriptModule("Warp")
	pWarpToOna3.SetInterruptable(1)
	pScript = pWarpToOna3.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.Ona.Ona3")
	pScript.SetDestinationPlacementName("NightEnter")
	pScript.SetWarpDuration(10)
	# Done creating PlainAI WarpToOna3
	#########################################
	#########################################
	# Creating ConditionalAI FirstWarpTimer at (141, 215)
	## Conditions:
	#### Condition Timer
	pTimer = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 10)
	## Evaluation function:
	def EvalFunc(bTimer):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bTimer):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pFirstWarpTimer = App.ConditionalAI_Create(pShip, "FirstWarpTimer")
	pFirstWarpTimer.SetInterruptable(1)
	pFirstWarpTimer.SetContainedAI(pWarpToOna3)
	pFirstWarpTimer.AddCondition(pTimer)
	pFirstWarpTimer.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI FirstWarpTimer
	#########################################
	#########################################
	# Creating CompoundAI TractorOnaPods at (261, 218)
	import AI.Compound.TractorDockTargets
	pTractorOnaPods = AI.Compound.TractorDockTargets.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode6.E6M2.E6M2", "g_pOnaPodTargets"))
	# Done creating CompoundAI TractorOnaPods
	#########################################
	#########################################
	# Creating SequenceAI OnaSequence at (32, 351)
	pOnaSequence = App.SequenceAI_Create(pShip, "OnaSequence")
	pOnaSequence.SetInterruptable(1)
	pOnaSequence.SetLoopCount(1)
	pOnaSequence.SetResetIfInterrupted(1)
	pOnaSequence.SetDoubleCheckAllDone(0)
	pOnaSequence.SetSkipDormant(0)
	# SeqBlock is at (202, 326)
	pOnaSequence.AddAI(pFirstWarpTimer)
	pOnaSequence.AddAI(pTractorOnaPods)
	# Done creating SequenceAI OnaSequence
	#########################################
	return pOnaSequence
