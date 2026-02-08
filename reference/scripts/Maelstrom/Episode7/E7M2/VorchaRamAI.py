import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI Ram_Warbird at (260, 201)
	pRam_Warbird = App.PlainAI_Create(pShip, "Ram_Warbird")
	pRam_Warbird.SetScriptModule("Ram")
	pRam_Warbird.SetInterruptable(1)
	pScript = pRam_Warbird.GetScriptInstance()
	pScript.SetTargetObjectName("Chairo")
	pScript.SetMaximumSpeed(1.25)
	# Done creating PlainAI Ram_Warbird
	#########################################
	#########################################
	# Creating ConditionalAI InRange at (159, 221)
	## Conditions:
	#### Condition Range1
	pRange1 = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 60, "JonKa", "Chairo")
	## Evaluation function:
	def EvalFunc(bRange1):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bRange1:
			return ACTIVE
		return DONE
	## The ConditionalAI:
	pInRange = App.ConditionalAI_Create(pShip, "InRange")
	pInRange.SetInterruptable(1)
	pInRange.SetContainedAI(pRam_Warbird)
	pInRange.AddCondition(pRange1)
	pInRange.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI InRange
	#########################################
	#########################################
	# Creating PlainAI Ram_Warbird_2 at (280, 158)
	pRam_Warbird_2 = App.PlainAI_Create(pShip, "Ram_Warbird_2")
	pRam_Warbird_2.SetScriptModule("Ram")
	pRam_Warbird_2.SetInterruptable(1)
	pScript = pRam_Warbird_2.GetScriptInstance()
	pScript.SetTargetObjectName("Chairo")
	pScript.SetMaximumSpeed(2.5)
	# Done creating PlainAI Ram_Warbird_2
	#########################################
	#########################################
	# Creating ConditionalAI InRange_2 at (172, 178)
	## Conditions:
	#### Condition Range2
	pRange2 = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 120, "JonKa", "Chairo")
	## Evaluation function:
	def EvalFunc(bRange2):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bRange2:
			return ACTIVE
		return DONE
	## The ConditionalAI:
	pInRange_2 = App.ConditionalAI_Create(pShip, "InRange_2")
	pInRange_2.SetInterruptable(1)
	pInRange_2.SetContainedAI(pRam_Warbird_2)
	pInRange_2.AddCondition(pRange2)
	pInRange_2.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI InRange_2
	#########################################
	#########################################
	# Creating PlainAI Ram_Warbird_3 at (294, 114)
	pRam_Warbird_3 = App.PlainAI_Create(pShip, "Ram_Warbird_3")
	pRam_Warbird_3.SetScriptModule("Ram")
	pRam_Warbird_3.SetInterruptable(1)
	pScript = pRam_Warbird_3.GetScriptInstance()
	pScript.SetTargetObjectName("Chairo")
	pScript.SetMaximumSpeed(3.75)
	# Done creating PlainAI Ram_Warbird_3
	#########################################
	#########################################
	# Creating ConditionalAI InRange_3 at (190, 134)
	## Conditions:
	#### Condition Range3
	pRange3 = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 180, "JonKa", "Chairo")
	## Evaluation function:
	def EvalFunc(bRange3):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bRange3:
			return ACTIVE
		return DONE
	## The ConditionalAI:
	pInRange_3 = App.ConditionalAI_Create(pShip, "InRange_3")
	pInRange_3.SetInterruptable(1)
	pInRange_3.SetContainedAI(pRam_Warbird_3)
	pInRange_3.AddCondition(pRange3)
	pInRange_3.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI InRange_3
	#########################################
	#########################################
	# Creating PlainAI Ram_Warbird_4 at (209, 81)
	pRam_Warbird_4 = App.PlainAI_Create(pShip, "Ram_Warbird_4")
	pRam_Warbird_4.SetScriptModule("Ram")
	pRam_Warbird_4.SetInterruptable(1)
	pScript = pRam_Warbird_4.GetScriptInstance()
	pScript.SetTargetObjectName("Chairo")
	pScript.SetMaximumSpeed(5)
	# Done creating PlainAI Ram_Warbird_4
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (50, 50)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (149, 57)
	pPriorityList.AddAI(pInRange, 1)
	pPriorityList.AddAI(pInRange_2, 2)
	pPriorityList.AddAI(pInRange_3, 3)
	pPriorityList.AddAI(pRam_Warbird_4, 4)
	# Done creating PriorityListAI PriorityList
	#########################################
	return pPriorityList
