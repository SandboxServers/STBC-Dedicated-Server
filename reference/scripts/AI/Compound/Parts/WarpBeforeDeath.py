import App

def CreateAI(pShip, dKeywords, fFraction = 0.1):

	#########################################
	# Creating PlainAI WarpOut at (165, 154)
	pWarpOut = App.PlainAI_Create(pShip, "WarpOut")
	pWarpOut.SetScriptModule("Warp")
	pWarpOut.SetInterruptable(0)
	# Done creating PlainAI WarpOut
	#########################################
	#########################################
	# Creating ConditionalAI WarpOutBeforeDeath at (163, 215)
	## Conditions:
	#### Condition FlagSet
	pFlagSet = App.ConditionScript_Create("Conditions.ConditionFlagSet", "ConditionFlagSet", "WarpOutBeforeDying", dKeywords)
	#### Condition CriticalSystemLow
	pCriticalSystemLow = App.ConditionScript_Create("Conditions.ConditionCriticalSystemBelow", "ConditionCriticalSystemBelow", pShip.GetName(), fFraction)
	#### Condition WarpDisabled
	pWarpDisabled = App.ConditionScript_Create("Conditions.ConditionSystemDisabled", "ConditionSystemDisabled", pShip.GetName(), App.CT_WARP_ENGINE_SUBSYSTEM, 1)
	## Evaluation function:
	def EvalFunc(bFlagSet, bCriticalSystemLow, bWarpDisabled):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if not bFlagSet:
			return DONE
		if (not bWarpDisabled)  and  bCriticalSystemLow:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pWarpOutBeforeDeath = App.ConditionalAI_Create(pShip, "WarpOutBeforeDeath")
	pWarpOutBeforeDeath.SetInterruptable(1)
	pWarpOutBeforeDeath.SetContainedAI(pWarpOut)
	pWarpOutBeforeDeath.AddCondition(pFlagSet)
	pWarpOutBeforeDeath.AddCondition(pCriticalSystemLow)
	pWarpOutBeforeDeath.AddCondition(pWarpDisabled)
	pWarpOutBeforeDeath.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI WarpOutBeforeDeath
	#########################################
	return pWarpOutBeforeDeath
