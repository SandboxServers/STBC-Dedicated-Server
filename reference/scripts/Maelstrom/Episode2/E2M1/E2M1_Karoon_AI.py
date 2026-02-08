import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI Call_InTractorRange at (135, 172)
	pCall_InTractorRange = App.PlainAI_Create(pShip, "Call_InTractorRange")
	pCall_InTractorRange.SetScriptModule("RunScript")
	pCall_InTractorRange.SetInterruptable(1)
	pScript = pCall_InTractorRange.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode2.E2M1.E2M1")
	pScript.SetFunction("InTractorRange")
	# Done creating PlainAI Call_InTractorRange
	#########################################
	#########################################
	# Creating ConditionalAI PlayerIsClose at (137, 225)
	## Conditions:
	#### Condition PlayerClose
	pPlayerClose = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 114, pShip.GetName(), "player")
	## Evaluation function:
	def EvalFunc(bPlayerClose):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bPlayerClose:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pPlayerIsClose = App.ConditionalAI_Create(pShip, "PlayerIsClose")
	pPlayerIsClose.SetInterruptable(1)
	pPlayerIsClose.SetContainedAI(pCall_InTractorRange)
	pPlayerIsClose.AddCondition(pPlayerClose)
	pPlayerIsClose.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI PlayerIsClose
	#########################################
	#########################################
	# Creating PlainAI Call_KaroonAlmostDestroyed at (269, 159)
	pCall_KaroonAlmostDestroyed = App.PlainAI_Create(pShip, "Call_KaroonAlmostDestroyed")
	pCall_KaroonAlmostDestroyed.SetScriptModule("RunScript")
	pCall_KaroonAlmostDestroyed.SetInterruptable(1)
	pScript = pCall_KaroonAlmostDestroyed.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode2.E2M1.E2M1")
	pScript.SetFunction("KaroonAlmostDestroyed")
	# Done creating PlainAI Call_KaroonAlmostDestroyed
	#########################################
	#########################################
	# Creating ConditionalAI IfHullBelow50 at (269, 219)
	## Conditions:
	#### Condition HullBelow30
	pHullBelow30 = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName(), App.CT_HULL_SUBSYSTEM, 0.30)
	## Evaluation function:
	def EvalFunc(bHullBelow30):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bHullBelow30:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pIfHullBelow50 = App.ConditionalAI_Create(pShip, "IfHullBelow50")
	pIfHullBelow50.SetInterruptable(1)
	pIfHullBelow50.SetContainedAI(pCall_KaroonAlmostDestroyed)
	pIfHullBelow50.AddCondition(pHullBelow30)
	pIfHullBelow50.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI IfHullBelow50
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (117, 292)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (225, 274)
	pPriorityList.AddAI(pPlayerIsClose, 1)
	pPriorityList.AddAI(pIfHullBelow50, 2)
	# Done creating PriorityListAI PriorityList
	#########################################
	return pPriorityList
