import App

def CreateAI(pShip, *lsTargets):
	
	#########################################
	# Creating PlainAI Stay at (79, 111)
	pStay = App.PlainAI_Create(pShip, "Stay")
	pStay.SetScriptModule("Stay")
	pStay.SetInterruptable(1)
	# Done creating PlainAI Stay
	#########################################
	#########################################
	# Creating ConditionalAI SensorsDead at (76, 184)
	## Conditions:
	#### Condition Disabled
	pDisabled = App.ConditionScript_Create("Conditions.ConditionSystemDisabled", "ConditionSystemDisabled", pShip.GetName(), App.CT_SENSOR_SUBSYSTEM, 1)
	## Evaluation function:
	def EvalFunc(bDisabled):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bDisabled:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pSensorsDead = App.ConditionalAI_Create(pShip, "SensorsDead")
	pSensorsDead.SetInterruptable(1)
	pSensorsDead.SetContainedAI(pStay)
	pSensorsDead.AddCondition(pDisabled)
	pSensorsDead.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI SensorsDead
	#########################################
	#########################################
	# Creating PlainAI Attack at (200, 109)
	pAttack = App.PlainAI_Create(pShip, "Attack")
	pAttack.SetScriptModule("StarbaseAttack")
	pAttack.SetInterruptable(1)
	pScript = pAttack.GetScriptInstance()
	pScript.SetTargets(lsTargets)
	# Done creating PlainAI Attack
	#########################################
	#########################################
	# Creating ConditionalAI TargetsInSet at (184, 184)
	## Conditions:
	#### Condition SameSet
	pSameSet = App.ConditionScript_Create("Conditions.ConditionAnyInSameSet", "ConditionAnyInSameSet", pShip.GetName(), lsTargets)
	## Evaluation function:
	def EvalFunc(bSameSet):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bSameSet:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pTargetsInSet = App.ConditionalAI_Create(pShip, "TargetsInSet")
	pTargetsInSet.SetInterruptable(1)
	pTargetsInSet.SetContainedAI(pAttack)
	pTargetsInSet.AddCondition(pSameSet)
	pTargetsInSet.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI TargetsInSet
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (42, 243)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (146, 250)
	pPriorityList.AddAI(pSensorsDead, 1)
	pPriorityList.AddAI(pTargetsInSet, 2)
	# Done creating PriorityListAI PriorityList
	#########################################
	return pPriorityList
