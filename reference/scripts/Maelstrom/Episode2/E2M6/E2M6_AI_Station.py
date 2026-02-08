import App
def CreateAI(pShip, fWaitTime):

	#########################################
	# Creating PlainAI Call_StationTakingDamage at (46, 166)
	pCall_StationTakingDamage = App.PlainAI_Create(pShip, "Call_StationTakingDamage")
	pCall_StationTakingDamage.SetScriptModule("RunScript")
	pCall_StationTakingDamage.SetInterruptable(1)
	pScript = pCall_StationTakingDamage.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode2.E2M6.E2M6")
	pScript.SetFunction("StationTakingDamage")
	# Done creating PlainAI Call_StationTakingDamage
	#########################################
	#########################################
	# Creating ConditionalAI HeavlyDamaged at (46, 221)
	## Conditions:
	#### Condition HullUnder25
	pHullUnder25 = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName(), App.CT_HULL_SUBSYSTEM, 0.25)
	#### Condition PowerPlantUnder25
	pPowerPlantUnder25 = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName(), App.CT_POWER_SUBSYSTEM, 0.25)
	## Evaluation function:
	def EvalFunc(bHullUnder25, bPowerPlantUnder25):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bHullUnder25 or bPowerPlantUnder25:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pHeavlyDamaged = App.ConditionalAI_Create(pShip, "HeavlyDamaged")
	pHeavlyDamaged.SetInterruptable(1)
	pHeavlyDamaged.SetContainedAI(pCall_StationTakingDamage)
	pHeavlyDamaged.AddCondition(pHullUnder25)
	pHeavlyDamaged.AddCondition(pPowerPlantUnder25)
	pHeavlyDamaged.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI HeavlyDamaged
	#########################################
	#########################################
	# Creating PlainAI Call_StationCallsForHelp at (144, 165)
	pCall_StationCallsForHelp = App.PlainAI_Create(pShip, "Call_StationCallsForHelp")
	pCall_StationCallsForHelp.SetScriptModule("RunScript")
	pCall_StationCallsForHelp.SetInterruptable(1)
	pScript = pCall_StationCallsForHelp.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode2.E2M6.E2M6")
	pScript.SetFunction("StationCallsForHelp")
	# Done creating PlainAI Call_StationCallsForHelp
	#########################################
	#########################################
	# Creating ConditionalAI CardsGettingClose at (144, 221)
	## Conditions:
	#### Condition GalorsWithin200
	pGalorsWithin200 = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 1142, pShip.GetName(), "Galor 5", "Galor 6")
	## Evaluation function:
	def EvalFunc(bGalorsWithin200):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bGalorsWithin200:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pCardsGettingClose = App.ConditionalAI_Create(pShip, "CardsGettingClose")
	pCardsGettingClose.SetInterruptable(1)
	pCardsGettingClose.SetContainedAI(pCall_StationCallsForHelp)
	pCardsGettingClose.AddCondition(pGalorsWithin200)
	pCardsGettingClose.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI CardsGettingClose
	#########################################
	#########################################
	# Creating PlainAI Call_DisableStationShields at (245, 146)
	pCall_DisableStationShields = App.PlainAI_Create(pShip, "Call_DisableStationShields")
	pCall_DisableStationShields.SetScriptModule("RunScript")
	pCall_DisableStationShields.SetInterruptable(1)
	pScript = pCall_DisableStationShields.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode2.E2M6.E2M6")
	pScript.SetFunction("DisableStationShields")
	pScript.SetArguments(None)
	# Done creating PlainAI Call_DisableStationShields
	#########################################
	#########################################
	# Creating ConditionalAI WaitTime at (242, 194)
	## Conditions:
	#### Condition ShortTime
	pShortTime = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", fWaitTime)
	## Evaluation function:
	def EvalFunc(bShortTime):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bShortTime:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pWaitTime = App.ConditionalAI_Create(pShip, "WaitTime")
	pWaitTime.SetInterruptable(1)
	pWaitTime.SetContainedAI(pCall_DisableStationShields)
	pWaitTime.AddCondition(pShortTime)
	pWaitTime.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI WaitTime
	#########################################
	#########################################
	# Creating ConditionalAI OneShieldDown at (239, 241)
	## Conditions:
	#### Condition TopShieldDown
	pTopShieldDown = App.ConditionScript_Create("Conditions.ConditionSingleShieldBelow", "ConditionSingleShieldBelow", pShip.GetName(), 0.10, App.ShieldClass.TOP_SHIELDS)
	#### Condition BottomShieldDown
	pBottomShieldDown = App.ConditionScript_Create("Conditions.ConditionSingleShieldBelow", "ConditionSingleShieldBelow", pShip.GetName(), 0.10, App.ShieldClass.BOTTOM_SHIELDS)
	#### Condition FrontShieldDown
	pFrontShieldDown = App.ConditionScript_Create("Conditions.ConditionSingleShieldBelow", "ConditionSingleShieldBelow", pShip.GetName(), 0.10, App.ShieldClass.FRONT_SHIELDS)
	#### Condition RearShieldDown
	pRearShieldDown = App.ConditionScript_Create("Conditions.ConditionSingleShieldBelow", "ConditionSingleShieldBelow", pShip.GetName(), 0.10, App.ShieldClass.REAR_SHIELDS)
	#### Condition LeftShieldDown
	pLeftShieldDown = App.ConditionScript_Create("Conditions.ConditionSingleShieldBelow", "ConditionSingleShieldBelow", pShip.GetName(), 0.10, App.ShieldClass.LEFT_SHIELDS)
	#### Condition RightShieldDown
	pRightShieldDown = App.ConditionScript_Create("Conditions.ConditionSingleShieldBelow", "ConditionSingleShieldBelow", pShip.GetName(), 0.10, App.ShieldClass.RIGHT_SHIELDS)
	## Evaluation function:
	def EvalFunc(bTopShieldDown, bBottomShieldDown, bFrontShieldDown, bRearShieldDown, bLeftShieldDown, bRightShieldDown):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bTopShieldDown or bBottomShieldDown or bFrontShieldDown or bRearShieldDown or bLeftShieldDown or bRightShieldDown:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pOneShieldDown = App.ConditionalAI_Create(pShip, "OneShieldDown")
	pOneShieldDown.SetInterruptable(1)
	pOneShieldDown.SetContainedAI(pWaitTime)
	pOneShieldDown.AddCondition(pTopShieldDown)
	pOneShieldDown.AddCondition(pBottomShieldDown)
	pOneShieldDown.AddCondition(pFrontShieldDown)
	pOneShieldDown.AddCondition(pRearShieldDown)
	pOneShieldDown.AddCondition(pLeftShieldDown)
	pOneShieldDown.AddCondition(pRightShieldDown)
	pOneShieldDown.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI OneShieldDown
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (12, 294)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (130, 302)
	pPriorityList.AddAI(pHeavlyDamaged, 1)
	pPriorityList.AddAI(pCardsGettingClose, 2)
	pPriorityList.AddAI(pOneShieldDown, 3)
	# Done creating PriorityListAI PriorityList
	#########################################
	return pPriorityList
