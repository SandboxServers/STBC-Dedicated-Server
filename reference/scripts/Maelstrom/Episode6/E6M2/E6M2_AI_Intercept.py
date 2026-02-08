import App
def CreateAI(pShip, sTargetName):
	#########################################
	# Creating PlainAI InterceptTarget at (79, 71)
	pInterceptTarget = App.PlainAI_Create(pShip, "InterceptTarget")
	pInterceptTarget.SetScriptModule("Intercept")
	pInterceptTarget.SetInterruptable(1)
	pScript = pInterceptTarget.GetScriptInstance()
	pScript.SetTargetObjectName(sTargetName)
	pScript.SetInterceptDistance(0)
	# Done creating PlainAI InterceptTarget
	#########################################
	#########################################
	# Creating ConditionalAI TargetNotClose at (83, 129)
	## Conditions:
	#### Condition IsTargetClose
	pIsTargetClose = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 57, pShip.GetName(), sTargetName)
	## Evaluation function:
	def EvalFunc(bIsTargetClose):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if(bIsTargetClose):
			return DONE
		return ACTIVE
	## The ConditionalAI:
	pTargetNotClose = App.ConditionalAI_Create(pShip, "TargetNotClose")
	pTargetNotClose.SetInterruptable(1)
	pTargetNotClose.SetContainedAI(pInterceptTarget)
	pTargetNotClose.AddCondition(pIsTargetClose)
	pTargetNotClose.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI TargetNotClose
	#########################################
	#########################################
	# Creating PlainAI StayPut at (312, 8)
	pStayPut = App.PlainAI_Create(pShip, "StayPut")
	pStayPut.SetScriptModule("Stay")
	pStayPut.SetInterruptable(1)
	# Done creating PlainAI StayPut
	#########################################
	#########################################
	# Creating ConditionalAI TargetIsClose at (308, 55)
	## Conditions:
	#### Condition TargetClose
	pTargetClose = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 10, pShip.GetName(), sTargetName)
	## Evaluation function:
	def EvalFunc(bTargetClose):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bTargetClose):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pTargetIsClose = App.ConditionalAI_Create(pShip, "TargetIsClose")
	pTargetIsClose.SetInterruptable(1)
	pTargetIsClose.SetContainedAI(pStayPut)
	pTargetIsClose.AddCondition(pTargetClose)
	pTargetIsClose.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI TargetIsClose
	#########################################
	#########################################
	# Creating PlainAI FaceAway at (461, 9)
	pFaceAway = App.PlainAI_Create(pShip, "FaceAway")
	pFaceAway.SetScriptModule("Flee")
	pFaceAway.SetInterruptable(1)
	pScript = pFaceAway.GetScriptInstance()
	pScript.SetFleeFromGroup(sTargetName)
	pScript.SetSpeed(0)
	# Done creating PlainAI FaceAway
	#########################################
	#########################################
	# Creating ConditionalAI InPosition at (415, 68)
	## Conditions:
	#### Condition FacingAway
	pFacingAway = App.ConditionScript_Create("Conditions.ConditionFacingToward", "ConditionFacingToward", "player", sTargetName, 20.0, App.TGPoint3_GetModelBackward())
	## Evaluation function:
	def EvalFunc(bFacingAway):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if(bFacingAway):
			return DORMANT
		return ACTIVE
	## The ConditionalAI:
	pInPosition = App.ConditionalAI_Create(pShip, "InPosition")
	pInPosition.SetInterruptable(1)
	pInPosition.SetContainedAI(pFaceAway)
	pInPosition.AddCondition(pFacingAway)
	pInPosition.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI InPosition
	#########################################
	#########################################
	# Creating PlainAI CallInPosition at (475, 128)
	pCallInPosition = App.PlainAI_Create(pShip, "CallInPosition")
	pCallInPosition.SetScriptModule("RunScript")
	pCallInPosition.SetInterruptable(1)
	pScript = pCallInPosition.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode6.E6M2.E6M2")
	pScript.SetFunction("InPosition")
	# Done creating PlainAI CallInPosition
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (257, 113)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (361, 122)
	pPriorityList.AddAI(pTargetIsClose, 1)
	pPriorityList.AddAI(pInPosition, 2)
	pPriorityList.AddAI(pCallInPosition, 3)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating ConditionalAI StillNear at (216, 164)
	## Conditions:
	#### Condition Near
	pNear = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 85, pShip.GetName(), sTargetName)
	## Evaluation function:
	def EvalFunc(bNear):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bNear:
			return ACTIVE
		return DONE
	## The ConditionalAI:
	pStillNear = App.ConditionalAI_Create(pShip, "StillNear")
	pStillNear.SetInterruptable(1)
	pStillNear.SetContainedAI(pPriorityList)
	pStillNear.AddCondition(pNear)
	pStillNear.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI StillNear
	#########################################
	#########################################
	# Creating SequenceAI Sequence at (27, 222)
	pSequence = App.SequenceAI_Create(pShip, "Sequence")
	pSequence.SetInterruptable(1)
	pSequence.SetLoopCount(-1)
	pSequence.SetResetIfInterrupted(1)
	pSequence.SetDoubleCheckAllDone(1)
	pSequence.SetSkipDormant(0)
	# SeqBlock is at (184, 223)
	pSequence.AddAI(pTargetNotClose)
	pSequence.AddAI(pStillNear)
	# Done creating SequenceAI Sequence
	#########################################
	return pSequence
