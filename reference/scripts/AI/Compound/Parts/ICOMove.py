import App

def CreateAI(pShip, sTarget, dKeywords, fForwardBias = 0.0):

	#########################################
	# Creating PlainAI ICO_MoveWithWeapons at (207, 67)
	pICO_MoveWithWeapons = App.PlainAI_Create(pShip, "ICO_MoveWithWeapons")
	pICO_MoveWithWeapons.SetScriptModule("IntelligentCircleObject")
	pICO_MoveWithWeapons.SetInterruptable(1)
	pScript = pICO_MoveWithWeapons.GetScriptInstance()
	pScript.SetFollowObjectName(sTarget)
	pScript.SetForwardBias(fForwardBias)
	# Done creating PlainAI ICO_MoveWithWeapons
	#########################################
	#########################################
	# Creating ConditionalAI UseSideWeapons at (212, 117)
	## Conditions:
	#### Condition UseSideArcs
	pUseSideArcs = App.ConditionScript_Create("Conditions.ConditionFlagSet", "ConditionFlagSet", "UseSideArcs", dKeywords)
	## Evaluation function:
	def EvalFunc(bUseSideArcs):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bUseSideArcs:
			return ACTIVE
		return DONE
	## The ConditionalAI:
	pUseSideWeapons = App.ConditionalAI_Create(pShip, "UseSideWeapons")
	pUseSideWeapons.SetInterruptable(1)
	pUseSideWeapons.SetContainedAI(pICO_MoveWithWeapons)
	pUseSideWeapons.AddCondition(pUseSideArcs)
	pUseSideWeapons.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI UseSideWeapons
	#########################################
	#########################################
	# Creating PlainAI ICO_MoveNoWeapons at (315, 121)
	pICO_MoveNoWeapons = App.PlainAI_Create(pShip, "ICO_MoveNoWeapons")
	pICO_MoveNoWeapons.SetScriptModule("IntelligentCircleObject")
	pICO_MoveNoWeapons.SetInterruptable(1)
	pScript = pICO_MoveNoWeapons.GetScriptInstance()
	pScript.SetFollowObjectName(sTarget)
	pScript.SetShieldAndWeaponImportance(1.0, 0.0)
	pScript.SetForwardBias(fForwardBias)
	# Done creating PlainAI ICO_MoveNoWeapons
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (173, 189)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (292, 188)
	pPriorityList.AddAI(pUseSideWeapons, 1)
	pPriorityList.AddAI(pICO_MoveNoWeapons, 2)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating ConditionalAI UseShields at (170, 252)
	## Conditions:
	#### Condition FlagSet
	pFlagSet = App.ConditionScript_Create("Conditions.ConditionFlagSet", "ConditionFlagSet", "SmartShields", dKeywords)
	## Evaluation function:
	def EvalFunc(bFlagSet):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bFlagSet:
			return ACTIVE
		return DONE
	## The ConditionalAI:
	pUseShields = App.ConditionalAI_Create(pShip, "UseShields")
	pUseShields.SetInterruptable(1)
	pUseShields.SetContainedAI(pPriorityList)
	pUseShields.AddCondition(pFlagSet)
	pUseShields.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI UseShields
	#########################################
	#########################################
	# Creating PlainAI ICO_MoveNoShields at (346, 202)
	pICO_MoveNoShields = App.PlainAI_Create(pShip, "ICO_MoveNoShields")
	pICO_MoveNoShields.SetScriptModule("IntelligentCircleObject")
	pICO_MoveNoShields.SetInterruptable(1)
	pScript = pICO_MoveNoShields.GetScriptInstance()
	pScript.SetFollowObjectName(sTarget)
	pScript.SetShieldAndWeaponImportance(0.0, 1.0)
	pScript.SetForwardBias(fForwardBias)
	# Done creating PlainAI ICO_MoveNoShields
	#########################################
	#########################################
	# Creating ConditionalAI UseSideWeapons_2 at (293, 255)
	## Conditions:
	#### Condition UseSideArcs
	pUseSideArcs = App.ConditionScript_Create("Conditions.ConditionFlagSet", "ConditionFlagSet", "UseSideArcs", dKeywords)
	## Evaluation function:
	def EvalFunc(bUseSideArcs):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bUseSideArcs:
			return ACTIVE
		return DONE
	## The ConditionalAI:
	pUseSideWeapons_2 = App.ConditionalAI_Create(pShip, "UseSideWeapons_2")
	pUseSideWeapons_2.SetInterruptable(1)
	pUseSideWeapons_2.SetContainedAI(pICO_MoveNoShields)
	pUseSideWeapons_2.AddCondition(pUseSideArcs)
	pUseSideWeapons_2.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI UseSideWeapons_2
	#########################################
	#########################################
	# Creating PlainAI ICO_MoveNoWeaponsNoShields at (359, 315)
	pICO_MoveNoWeaponsNoShields = App.PlainAI_Create(pShip, "ICO_MoveNoWeaponsNoShields")
	pICO_MoveNoWeaponsNoShields.SetScriptModule("IntelligentCircleObject")
	pICO_MoveNoWeaponsNoShields.SetInterruptable(1)
	pScript = pICO_MoveNoWeaponsNoShields.GetScriptInstance()
	pScript.SetFollowObjectName(sTarget)
	pScript.SetShieldAndWeaponImportance(0.0, 0.0)
	pScript.SetForwardBias(fForwardBias)
	# Done creating PlainAI ICO_MoveNoWeaponsNoShields
	#########################################
	#########################################
	# Creating PriorityListAI ICOMovePriorities at (94, 317)
	pICOMovePriorities = App.PriorityListAI_Create(pShip, "ICOMovePriorities")
	pICOMovePriorities.SetInterruptable(1)
	# SeqBlock is at (247, 314)
	pICOMovePriorities.AddAI(pUseShields, 1)
	pICOMovePriorities.AddAI(pUseSideWeapons_2, 2)
	pICOMovePriorities.AddAI(pICO_MoveNoWeaponsNoShields, 3)
	# Done creating PriorityListAI ICOMovePriorities
	#########################################
	return pICOMovePriorities
