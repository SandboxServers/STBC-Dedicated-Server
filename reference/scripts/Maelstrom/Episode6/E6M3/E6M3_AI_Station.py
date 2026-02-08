import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI Call_StationTakingDamage at (284, 168)
	pCall_StationTakingDamage = App.PlainAI_Create(pShip, "Call_StationTakingDamage")
	pCall_StationTakingDamage.SetScriptModule("RunScript")
	pCall_StationTakingDamage.SetInterruptable(1)
	pScript = pCall_StationTakingDamage.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode6.E6M3.E6M3")
	pScript.SetFunction("StationTakingDamage")
	# Done creating PlainAI Call_StationTakingDamage
	#########################################
	#########################################
	# Creating ConditionalAI HullTakingDamage at (207, 220)
	## Conditions:
	#### Condition HullAt50
	pHullAt50 = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName(), App.CT_HULL_SUBSYSTEM, 0.50)
	## Evaluation function:
	def EvalFunc(bHullAt50):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bHullAt50):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pHullTakingDamage = App.ConditionalAI_Create(pShip, "HullTakingDamage")
	pHullTakingDamage.SetInterruptable(1)
	pHullTakingDamage.SetContainedAI(pCall_StationTakingDamage)
	pHullTakingDamage.AddCondition(pHullAt50)
	pHullTakingDamage.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI HullTakingDamage
	#########################################
	return pHullTakingDamage
