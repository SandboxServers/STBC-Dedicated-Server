import App

def CreateAI(pShip):
	#########################################
	# Creating PlainAI Call_TransportTakingDamage at (90, 148)
	pCall_TransportTakingDamage = App.PlainAI_Create(pShip, "Call_TransportTakingDamage")
	pCall_TransportTakingDamage.SetScriptModule("RunScript")
	pCall_TransportTakingDamage.SetInterruptable(1)
	pScript = pCall_TransportTakingDamage.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode6.E6M1.E6M1")
	pScript.SetFunction("TransportTakingDamage")
	pScript.SetArguments(None, pShip.GetName())
	# Done creating PlainAI Call_TransportTakingDamage
	#########################################
	#########################################
	# Creating ConditionalAI TakingDamage at (92, 205)
	## Conditions:
	#### Condition CriticalDamage
	pCriticalDamage = App.ConditionScript_Create("Conditions.ConditionCriticalSystemBelow", "ConditionCriticalSystemBelow", pShip.GetName(), 0.5)
	## Evaluation function:
	def EvalFunc(bCriticalDamage):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bCriticalDamage:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pTakingDamage = App.ConditionalAI_Create(pShip, "TakingDamage")
	pTakingDamage.SetInterruptable(1)
	pTakingDamage.SetContainedAI(pCall_TransportTakingDamage)
	pTakingDamage.AddCondition(pCriticalDamage)
	pTakingDamage.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI TakingDamage
	#########################################
	#########################################
	# Creating PlainAI StayPut at (197, 201)
	pStayPut = App.PlainAI_Create(pShip, "StayPut")
	pStayPut.SetScriptModule("Stay")
	pStayPut.SetInterruptable(1)
	# Done creating PlainAI StayPut
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (30, 277)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (145, 272)
	pPriorityList.AddAI(pTakingDamage, 1)
	pPriorityList.AddAI(pStayPut, 2)
	# Done creating PriorityListAI PriorityList
	#########################################
	return pPriorityList
