import App

def CreateAI(pShip):
	#########################################
	# Creating PlainAI Call_SovDamaged at (97, 150)
	pCall_SovDamaged = App.PlainAI_Create(pShip, "Call_SovDamaged")
	pCall_SovDamaged.SetScriptModule("RunScript")
	pCall_SovDamaged.SetInterruptable(1)
	pScript = pCall_SovDamaged.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode2.E2M0.E2M0")
	pScript.SetFunction("SovDamaged")
	# Done creating PlainAI Call_SovDamaged
	#########################################
	#########################################
	# Creating ConditionalAI LotsOfDamageAndShieldDown at (96, 218)
	## Conditions:
	#### Condition LotsOfCriticalDamage
	pLotsOfCriticalDamage = App.ConditionScript_Create("Conditions.ConditionCriticalSystemBelow", "ConditionCriticalSystemBelow", pShip.GetName(), 0.5)
	#### Condition FrontShieldAt0
	pFrontShieldAt0 = App.ConditionScript_Create("Conditions.ConditionSingleShieldBelow", "ConditionSingleShieldBelow", pShip.GetName(), 0.2, App.ShieldClass.FRONT_SHIELDS)
	#### Condition RearShieldAt0
	pRearShieldAt0 = App.ConditionScript_Create("Conditions.ConditionSingleShieldBelow", "ConditionSingleShieldBelow", pShip.GetName(), 0.2, App.ShieldClass.REAR_SHIELDS)
	#### Condition TopShieldAt0
	pTopShieldAt0 = App.ConditionScript_Create("Conditions.ConditionSingleShieldBelow", "ConditionSingleShieldBelow", pShip.GetName(), 0.2, App.ShieldClass.TOP_SHIELDS)
	#### Condition BottomShieldAt0
	pBottomShieldAt0 = App.ConditionScript_Create("Conditions.ConditionSingleShieldBelow", "ConditionSingleShieldBelow", pShip.GetName(), 0.2, App.ShieldClass.BOTTOM_SHIELDS)
	#### Condition RightShieldAt0
	pRightShieldAt0 = App.ConditionScript_Create("Conditions.ConditionSingleShieldBelow", "ConditionSingleShieldBelow", pShip.GetName(), 0.2, App.ShieldClass.RIGHT_SHIELDS)
	#### Condition LeftShieldAt0
	pLeftShieldAt0 = App.ConditionScript_Create("Conditions.ConditionSingleShieldBelow", "ConditionSingleShieldBelow", pShip.GetName(), 0.2, App.ShieldClass.LEFT_SHIELDS)
	## Evaluation function:
	def EvalFunc(bLotsOfCriticalDamage, bFrontShieldAt0, bRearShieldAt0, bTopShieldAt0, bBottomShieldAt0, bRightShieldAt0, bLeftShieldAt0):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bLotsOfCriticalDamage and (bFrontShieldAt0 or bRearShieldAt0 or bTopShieldAt0 or bBottomShieldAt0 or bRightShieldAt0 or bLeftShieldAt0):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pLotsOfDamageAndShieldDown = App.ConditionalAI_Create(pShip, "LotsOfDamageAndShieldDown")
	pLotsOfDamageAndShieldDown.SetInterruptable(1)
	pLotsOfDamageAndShieldDown.SetContainedAI(pCall_SovDamaged)
	pLotsOfDamageAndShieldDown.AddCondition(pLotsOfCriticalDamage)
	pLotsOfDamageAndShieldDown.AddCondition(pFrontShieldAt0)
	pLotsOfDamageAndShieldDown.AddCondition(pRearShieldAt0)
	pLotsOfDamageAndShieldDown.AddCondition(pTopShieldAt0)
	pLotsOfDamageAndShieldDown.AddCondition(pBottomShieldAt0)
	pLotsOfDamageAndShieldDown.AddCondition(pRightShieldAt0)
	pLotsOfDamageAndShieldDown.AddCondition(pLeftShieldAt0)
	pLotsOfDamageAndShieldDown.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI LotsOfDamageAndShieldDown
	#########################################
	#########################################
	# Creating PlainAI StayPut_2 at (207, 162)
	pStayPut_2 = App.PlainAI_Create(pShip, "StayPut_2")
	pStayPut_2.SetScriptModule("Stay")
	pStayPut_2.SetInterruptable(1)
	# Done creating PlainAI StayPut_2
	#########################################
	#########################################
	# Creating PreprocessingAI RedAlert at (205, 221)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AlertLevel(App.ShipClass.RED_ALERT)
	## The PreprocessingAI:
	pRedAlert = App.PreprocessingAI_Create(pShip, "RedAlert")
	pRedAlert.SetInterruptable(1)
	pRedAlert.SetPreprocessingMethod(pScript, "Update")
	pRedAlert.SetContainedAI(pStayPut_2)
	# Done creating PreprocessingAI RedAlert
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (58, 284)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (177, 291)
	pPriorityList.AddAI(pLotsOfDamageAndShieldDown, 1)
	pPriorityList.AddAI(pRedAlert, 2)
	# Done creating PriorityListAI PriorityList
	#########################################
	return pPriorityList
