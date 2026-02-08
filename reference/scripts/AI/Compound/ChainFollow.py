import App

iIndex = 0

def CreateAI(pShip, kShips):
	global iIndex
	iIndex = kShips.index(pShip.GetName())
	for iAdditional in range(len(kShips), 8):
		kShips.append("")


	#########################################
	# Creating PlainAI FollowShip7 at (206, 331)
	pFollowShip7 = App.PlainAI_Create(pShip, "FollowShip7")
	pFollowShip7.SetScriptModule("FollowObject")
	pFollowShip7.SetInterruptable(1)
	pScript = pFollowShip7.GetScriptInstance()
	pScript.SetFollowObjectName(kShips[7])
	# Done creating PlainAI FollowShip7
	#########################################
	#########################################
	# Creating ConditionalAI FollowCondition7 at (108, 351)
	## Conditions:
	#### Condition ShipExists
	pShipExists = App.ConditionScript_Create("Conditions.ConditionExists", "ConditionExists", kShips[7])
	#### Condition WarpDisabled
	pWarpDisabled = App.ConditionScript_Create("Conditions.ConditionSystemDisabled", "ConditionSystemDisabled", kShips[7], App.CT_WARP_ENGINE_SUBSYSTEM)
	#### Condition WarpDestroyed
	pWarpDestroyed = App.ConditionScript_Create("Conditions.ConditionSystemDestroyed", "ConditionSystemDestroyed", kShips[7], App.CT_WARP_ENGINE_SUBSYSTEM)
	## Evaluation function:
	def EvalFunc(bShipExists, bWarpDisabled, bWarpDestroyed):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (iIndex <= 7) or not bShipExists or bWarpDisabled or bWarpDestroyed:
			return DORMANT
		return ACTIVE
	## The ConditionalAI:
	pFollowCondition7 = App.ConditionalAI_Create(pShip, "FollowCondition7")
	pFollowCondition7.SetInterruptable(1)
	pFollowCondition7.SetContainedAI(pFollowShip7)
	pFollowCondition7.AddCondition(pShipExists)
	pFollowCondition7.AddCondition(pWarpDisabled)
	pFollowCondition7.AddCondition(pWarpDestroyed)
	pFollowCondition7.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI FollowCondition7
	#########################################
	#########################################
	# Creating PlainAI FollowShip6 at (226, 288)
	pFollowShip6 = App.PlainAI_Create(pShip, "FollowShip6")
	pFollowShip6.SetScriptModule("FollowObject")
	pFollowShip6.SetInterruptable(1)
	pScript = pFollowShip6.GetScriptInstance()
	pScript.SetFollowObjectName(kShips[6])
	# Done creating PlainAI FollowShip6
	#########################################
	#########################################
	# Creating ConditionalAI FollowCondition6 at (123, 308)
	## Conditions:
	#### Condition ShipExists
	pShipExists = App.ConditionScript_Create("Conditions.ConditionExists", "ConditionExists", kShips[6])
	#### Condition WarpDisabled
	pWarpDisabled = App.ConditionScript_Create("Conditions.ConditionSystemDisabled", "ConditionSystemDisabled", kShips[6], App.CT_WARP_ENGINE_SUBSYSTEM)
	#### Condition WarpDestroyed
	pWarpDestroyed = App.ConditionScript_Create("Conditions.ConditionSystemDestroyed", "ConditionSystemDestroyed", kShips[6], App.CT_WARP_ENGINE_SUBSYSTEM)
	## Evaluation function:
	def EvalFunc(bShipExists, bWarpDisabled, bWarpDestroyed):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (iIndex <= 6) or not bShipExists or bWarpDisabled or bWarpDestroyed:
			return DORMANT
		return ACTIVE
	## The ConditionalAI:
	pFollowCondition6 = App.ConditionalAI_Create(pShip, "FollowCondition6")
	pFollowCondition6.SetInterruptable(1)
	pFollowCondition6.SetContainedAI(pFollowShip6)
	pFollowCondition6.AddCondition(pShipExists)
	pFollowCondition6.AddCondition(pWarpDisabled)
	pFollowCondition6.AddCondition(pWarpDestroyed)
	pFollowCondition6.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI FollowCondition6
	#########################################
	#########################################
	# Creating PlainAI FollowShip5 at (239, 243)
	pFollowShip5 = App.PlainAI_Create(pShip, "FollowShip5")
	pFollowShip5.SetScriptModule("FollowObject")
	pFollowShip5.SetInterruptable(1)
	pScript = pFollowShip5.GetScriptInstance()
	pScript.SetFollowObjectName(kShips[5])
	# Done creating PlainAI FollowShip5
	#########################################
	#########################################
	# Creating ConditionalAI FollowCondition5 at (140, 263)
	## Conditions:
	#### Condition ShipExists
	pShipExists = App.ConditionScript_Create("Conditions.ConditionExists", "ConditionExists", kShips[5])
	#### Condition WarpDisabled
	pWarpDisabled = App.ConditionScript_Create("Conditions.ConditionSystemDisabled", "ConditionSystemDisabled", kShips[5], App.CT_WARP_ENGINE_SUBSYSTEM)
	#### Condition WarpDestroyed
	pWarpDestroyed = App.ConditionScript_Create("Conditions.ConditionSystemDestroyed", "ConditionSystemDestroyed", kShips[5], App.CT_WARP_ENGINE_SUBSYSTEM)
	## Evaluation function:
	def EvalFunc(bShipExists, bWarpDisabled, bWarpDestroyed):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (iIndex <= 5) or not bShipExists or bWarpDisabled or bWarpDestroyed:
			return DORMANT
		return ACTIVE
	## The ConditionalAI:
	pFollowCondition5 = App.ConditionalAI_Create(pShip, "FollowCondition5")
	pFollowCondition5.SetInterruptable(1)
	pFollowCondition5.SetContainedAI(pFollowShip5)
	pFollowCondition5.AddCondition(pShipExists)
	pFollowCondition5.AddCondition(pWarpDisabled)
	pFollowCondition5.AddCondition(pWarpDestroyed)
	pFollowCondition5.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI FollowCondition5
	#########################################
	#########################################
	# Creating PlainAI FollowShip4 at (257, 200)
	pFollowShip4 = App.PlainAI_Create(pShip, "FollowShip4")
	pFollowShip4.SetScriptModule("FollowObject")
	pFollowShip4.SetInterruptable(1)
	pScript = pFollowShip4.GetScriptInstance()
	pScript.SetFollowObjectName(kShips[4])
	# Done creating PlainAI FollowShip4
	#########################################
	#########################################
	# Creating ConditionalAI FollowCondition4 at (152, 220)
	## Conditions:
	#### Condition ShipExists
	pShipExists = App.ConditionScript_Create("Conditions.ConditionExists", "ConditionExists", kShips[4])
	#### Condition WarpDisabled
	pWarpDisabled = App.ConditionScript_Create("Conditions.ConditionSystemDisabled", "ConditionSystemDisabled", kShips[4], App.CT_WARP_ENGINE_SUBSYSTEM)
	#### Condition WarpDestroyed
	pWarpDestroyed = App.ConditionScript_Create("Conditions.ConditionSystemDestroyed", "ConditionSystemDestroyed", kShips[4], App.CT_WARP_ENGINE_SUBSYSTEM)
	## Evaluation function:
	def EvalFunc(bShipExists, bWarpDisabled, bWarpDestroyed):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (iIndex <= 4) or not bShipExists or bWarpDisabled or bWarpDestroyed:
			return DORMANT
		return ACTIVE
	## The ConditionalAI:
	pFollowCondition4 = App.ConditionalAI_Create(pShip, "FollowCondition4")
	pFollowCondition4.SetInterruptable(1)
	pFollowCondition4.SetContainedAI(pFollowShip4)
	pFollowCondition4.AddCondition(pShipExists)
	pFollowCondition4.AddCondition(pWarpDisabled)
	pFollowCondition4.AddCondition(pWarpDestroyed)
	pFollowCondition4.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI FollowCondition4
	#########################################
	#########################################
	# Creating PlainAI FollowShip3 at (277, 156)
	pFollowShip3 = App.PlainAI_Create(pShip, "FollowShip3")
	pFollowShip3.SetScriptModule("FollowObject")
	pFollowShip3.SetInterruptable(1)
	pScript = pFollowShip3.GetScriptInstance()
	pScript.SetFollowObjectName(kShips[3])
	# Done creating PlainAI FollowShip3
	#########################################
	#########################################
	# Creating ConditionalAI FollowCondition3 at (170, 176)
	## Conditions:
	#### Condition ShipExists
	pShipExists = App.ConditionScript_Create("Conditions.ConditionExists", "ConditionExists", kShips[3])
	#### Condition WarpDisabled
	pWarpDisabled = App.ConditionScript_Create("Conditions.ConditionSystemDisabled", "ConditionSystemDisabled", kShips[3], App.CT_WARP_ENGINE_SUBSYSTEM)
	#### Condition WarpDestroyed
	pWarpDestroyed = App.ConditionScript_Create("Conditions.ConditionSystemDestroyed", "ConditionSystemDestroyed", kShips[3], App.CT_WARP_ENGINE_SUBSYSTEM)
	## Evaluation function:
	def EvalFunc(bShipExists, bWarpDisabled, bWarpDestroyed):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (iIndex <= 3) or not bShipExists or bWarpDisabled or bWarpDestroyed:
			return DORMANT
		return ACTIVE
	## The ConditionalAI:
	pFollowCondition3 = App.ConditionalAI_Create(pShip, "FollowCondition3")
	pFollowCondition3.SetInterruptable(1)
	pFollowCondition3.SetContainedAI(pFollowShip3)
	pFollowCondition3.AddCondition(pShipExists)
	pFollowCondition3.AddCondition(pWarpDisabled)
	pFollowCondition3.AddCondition(pWarpDestroyed)
	pFollowCondition3.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI FollowCondition3
	#########################################
	#########################################
	# Creating PlainAI FollowShip2 at (294, 110)
	pFollowShip2 = App.PlainAI_Create(pShip, "FollowShip2")
	pFollowShip2.SetScriptModule("FollowObject")
	pFollowShip2.SetInterruptable(1)
	pScript = pFollowShip2.GetScriptInstance()
	pScript.SetFollowObjectName(kShips[2])
	# Done creating PlainAI FollowShip2
	#########################################
	#########################################
	# Creating ConditionalAI FollowCondition2 at (190, 130)
	## Conditions:
	#### Condition ShipExists
	pShipExists = App.ConditionScript_Create("Conditions.ConditionExists", "ConditionExists", kShips[2])
	#### Condition WarpDisabled
	pWarpDisabled = App.ConditionScript_Create("Conditions.ConditionSystemDisabled", "ConditionSystemDisabled", kShips[2], App.CT_WARP_ENGINE_SUBSYSTEM)
	#### Condition WarpDestroyed
	pWarpDestroyed = App.ConditionScript_Create("Conditions.ConditionSystemDestroyed", "ConditionSystemDestroyed", kShips[2], App.CT_WARP_ENGINE_SUBSYSTEM)
	## Evaluation function:
	def EvalFunc(bShipExists, bWarpDisabled, bWarpDestroyed):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (iIndex <= 2) or not bShipExists or bWarpDisabled or bWarpDestroyed:
			return DORMANT
		return ACTIVE
	## The ConditionalAI:
	pFollowCondition2 = App.ConditionalAI_Create(pShip, "FollowCondition2")
	pFollowCondition2.SetInterruptable(1)
	pFollowCondition2.SetContainedAI(pFollowShip2)
	pFollowCondition2.AddCondition(pShipExists)
	pFollowCondition2.AddCondition(pWarpDisabled)
	pFollowCondition2.AddCondition(pWarpDestroyed)
	pFollowCondition2.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI FollowCondition2
	#########################################
	#########################################
	# Creating PlainAI FollowShip1 at (305, 66)
	pFollowShip1 = App.PlainAI_Create(pShip, "FollowShip1")
	pFollowShip1.SetScriptModule("FollowObject")
	pFollowShip1.SetInterruptable(1)
	pScript = pFollowShip1.GetScriptInstance()
	pScript.SetFollowObjectName(kShips[1])
	# Done creating PlainAI FollowShip1
	#########################################
	#########################################
	# Creating ConditionalAI FollowCondition1 at (203, 86)
	## Conditions:
	#### Condition ShipExists
	pShipExists = App.ConditionScript_Create("Conditions.ConditionExists", "ConditionExists", kShips[1])
	#### Condition WarpDisabled
	pWarpDisabled = App.ConditionScript_Create("Conditions.ConditionSystemDisabled", "ConditionSystemDisabled", kShips[1], App.CT_WARP_ENGINE_SUBSYSTEM)
	#### Condition WarpDestroyed
	pWarpDestroyed = App.ConditionScript_Create("Conditions.ConditionSystemDestroyed", "ConditionSystemDestroyed", kShips[1], App.CT_WARP_ENGINE_SUBSYSTEM)
	## Evaluation function:
	def EvalFunc(bShipExists, bWarpDisabled, bWarpDestroyed):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (iIndex <= 1) or not bShipExists or bWarpDisabled or bWarpDestroyed:
			return DORMANT
		return ACTIVE
	## The ConditionalAI:
	pFollowCondition1 = App.ConditionalAI_Create(pShip, "FollowCondition1")
	pFollowCondition1.SetInterruptable(1)
	pFollowCondition1.SetContainedAI(pFollowShip1)
	pFollowCondition1.AddCondition(pShipExists)
	pFollowCondition1.AddCondition(pWarpDisabled)
	pFollowCondition1.AddCondition(pWarpDestroyed)
	pFollowCondition1.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI FollowCondition1
	#########################################
	#########################################
	# Creating PlainAI FollowShip0 at (307, 19)
	pFollowShip0 = App.PlainAI_Create(pShip, "FollowShip0")
	pFollowShip0.SetScriptModule("FollowObject")
	pFollowShip0.SetInterruptable(1)
	pScript = pFollowShip0.GetScriptInstance()
	pScript.SetFollowObjectName(kShips[0])
	# Done creating PlainAI FollowShip0
	#########################################
	#########################################
	# Creating ConditionalAI FollowCondition0 at (219, 39)
	## Conditions:
	#### Condition ShipExists
	pShipExists = App.ConditionScript_Create("Conditions.ConditionExists", "ConditionExists", kShips[0])
	#### Condition WarpDisabled
	pWarpDisabled = App.ConditionScript_Create("Conditions.ConditionSystemDisabled", "ConditionSystemDisabled", kShips[0], App.CT_WARP_ENGINE_SUBSYSTEM)
	#### Condition WarpDestroyed
	pWarpDestroyed = App.ConditionScript_Create("Conditions.ConditionSystemDestroyed", "ConditionSystemDestroyed", kShips[0], App.CT_WARP_ENGINE_SUBSYSTEM)
	## Evaluation function:
	def EvalFunc(bShipExists, bWarpDisabled, bWarpDestroyed):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (iIndex == 0) or not bShipExists or bWarpDisabled or bWarpDestroyed:
			return DORMANT
		return ACTIVE
	## The ConditionalAI:
	pFollowCondition0 = App.ConditionalAI_Create(pShip, "FollowCondition0")
	pFollowCondition0.SetInterruptable(1)
	pFollowCondition0.SetContainedAI(pFollowShip0)
	pFollowCondition0.AddCondition(pShipExists)
	pFollowCondition0.AddCondition(pWarpDisabled)
	pFollowCondition0.AddCondition(pWarpDestroyed)
	pFollowCondition0.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI FollowCondition0
	#########################################
	#########################################
	# Creating PriorityListAI PriorityFollow at (4, 4)
	pPriorityFollow = App.PriorityListAI_Create(pShip, "PriorityFollow")
	pPriorityFollow.SetInterruptable(1)
	# SeqBlock is at (98, 11)
	pPriorityFollow.AddAI(pFollowCondition7, 1)
	pPriorityFollow.AddAI(pFollowCondition6, 2)
	pPriorityFollow.AddAI(pFollowCondition5, 3)
	pPriorityFollow.AddAI(pFollowCondition4, 4)
	pPriorityFollow.AddAI(pFollowCondition3, 5)
	pPriorityFollow.AddAI(pFollowCondition2, 6)
	pPriorityFollow.AddAI(pFollowCondition1, 7)
	pPriorityFollow.AddAI(pFollowCondition0, 8)
	# Done creating PriorityListAI PriorityFollow
	#########################################
	return pPriorityFollow
