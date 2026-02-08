import App

def CreateAI(pShip, sTargetName):

	#########################################
	# Creating PlainAI CircleTarget at (50, 86)
	pCircleTarget = App.PlainAI_Create(pShip, "CircleTarget")
	pCircleTarget.SetScriptModule("CircleObject")
	pCircleTarget.SetInterruptable(1)
	pScript = pCircleTarget.GetScriptInstance()
	pScript.SetFollowObjectName(sTargetName)
	pScript.SetNearFacingVector(App.TGPoint3_GetModelLeft())
	pScript.SetRoughDistances(fNearDistance = 200, fFarDistance = 250)
	pScript.SetCircleSpeed(fSpeed = 1.0)
	# Done creating PlainAI CircleTarget
	#########################################
	#########################################
	# Creating ConditionalAI WarbirdsInOurSet at (52, 139)
	## Conditions:
	#### Condition WarbirdsInSet
	pWarbirdsInSet = App.ConditionScript_Create("Conditions.ConditionAllInSameSet", "ConditionAllInSameSet", pShip.GetName(), "Warbird 1", "Warbird 2")
	## Evaluation function:
	def EvalFunc(bWarbirdsInSet):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if not bWarbirdsInSet:
			return DONE
		return ACTIVE
	## The ConditionalAI:
	pWarbirdsInOurSet = App.ConditionalAI_Create(pShip, "WarbirdsInOurSet")
	pWarbirdsInOurSet.SetInterruptable(1)
	pWarbirdsInOurSet.SetContainedAI(pCircleTarget)
	pWarbirdsInOurSet.AddCondition(pWarbirdsInSet)
	pWarbirdsInOurSet.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI WarbirdsInOurSet
	#########################################
	#########################################
	# Creating PreprocessingAI Cloak at (54, 187)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.CloakShip(1)
	## The PreprocessingAI:
	pCloak = App.PreprocessingAI_Create(pShip, "Cloak")
	pCloak.SetInterruptable(1)
	pCloak.SetPreprocessingMethod(pScript, "Update")
	pCloak.SetContainedAI(pWarbirdsInOurSet)
	# Done creating PreprocessingAI Cloak
	#########################################
	#########################################
	# Creating PlainAI CircleTarget_2 at (149, 86)
	pCircleTarget_2 = App.PlainAI_Create(pShip, "CircleTarget_2")
	pCircleTarget_2.SetScriptModule("CircleObject")
	pCircleTarget_2.SetInterruptable(1)
	pScript = pCircleTarget_2.GetScriptInstance()
	pScript.SetFollowObjectName(sTargetName)
	pScript.SetNearFacingVector(App.TGPoint3_GetModelLeft())
	pScript.SetRoughDistances(fNearDistance = 200, fFarDistance = 250)
	pScript.SetCircleSpeed(fSpeed = 1.0)
	# Done creating PlainAI CircleTarget_2
	#########################################
	#########################################
	# Creating ConditionalAI ShortTimer at (146, 141)
	## Conditions:
	#### Condition TimerA
	pTimerA = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 10)
	## Evaluation function:
	def EvalFunc(bTimerA):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bTimerA:
			return DONE
		return ACTIVE
	## The ConditionalAI:
	pShortTimer = App.ConditionalAI_Create(pShip, "ShortTimer")
	pShortTimer.SetInterruptable(1)
	pShortTimer.SetContainedAI(pCircleTarget_2)
	pShortTimer.AddCondition(pTimerA)
	pShortTimer.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI ShortTimer
	#########################################
	#########################################
	# Creating PreprocessingAI Cloak_2 at (148, 190)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.CloakShip(1)
	## The PreprocessingAI:
	pCloak_2 = App.PreprocessingAI_Create(pShip, "Cloak_2")
	pCloak_2.SetInterruptable(1)
	pCloak_2.SetPreprocessingMethod(pScript, "Update")
	pCloak_2.SetContainedAI(pShortTimer)
	# Done creating PreprocessingAI Cloak_2
	#########################################
	#########################################
	# Creating PlainAI Call_KlingonsDecloak at (272, 80)
	pCall_KlingonsDecloak = App.PlainAI_Create(pShip, "Call_KlingonsDecloak")
	pCall_KlingonsDecloak.SetScriptModule("RunScript")
	pCall_KlingonsDecloak.SetInterruptable(1)
	pScript = pCall_KlingonsDecloak.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode2.E2M0.E2M0")
	pScript.SetFunction("KlingonsDecloak")
	pScript.SetArguments(None)
	# Done creating PlainAI Call_KlingonsDecloak
	#########################################
	#########################################
	# Creating PlainAI InterceptTarget at (358, 119)
	pInterceptTarget = App.PlainAI_Create(pShip, "InterceptTarget")
	pInterceptTarget.SetScriptModule("Intercept")
	pInterceptTarget.SetInterruptable(1)
	pScript = pInterceptTarget.GetScriptInstance()
	pScript.SetTargetObjectName(sTargetName)
	pScript.SetAddObjectRadius(bUseRadius = 1)
	# Done creating PlainAI InterceptTarget
	#########################################
	#########################################
	# Creating PlainAI StayPut at (449, 118)
	pStayPut = App.PlainAI_Create(pShip, "StayPut")
	pStayPut.SetScriptModule("Stay")
	pStayPut.SetInterruptable(1)
	# Done creating PlainAI StayPut
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (297, 181)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (421, 171)
	pPriorityList.AddAI(pInterceptTarget, 1)
	pPriorityList.AddAI(pStayPut, 2)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PreprocessingAI GreenAlert at (294, 238)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AlertLevel(App.ShipClass.GREEN_ALERT)
	## The PreprocessingAI:
	pGreenAlert = App.PreprocessingAI_Create(pShip, "GreenAlert")
	pGreenAlert.SetInterruptable(1)
	pGreenAlert.SetPreprocessingMethod(pScript, "Update")
	pGreenAlert.SetContainedAI(pPriorityList)
	# Done creating PreprocessingAI GreenAlert
	#########################################
	#########################################
	# Creating SequenceAI Sequence at (36, 254)
	pSequence = App.SequenceAI_Create(pShip, "Sequence")
	pSequence.SetInterruptable(1)
	pSequence.SetLoopCount(1)
	pSequence.SetResetIfInterrupted(1)
	pSequence.SetDoubleCheckAllDone(0)
	pSequence.SetSkipDormant(0)
	# SeqBlock is at (181, 251)
	pSequence.AddAI(pCloak)
	pSequence.AddAI(pCloak_2)
	pSequence.AddAI(pCall_KlingonsDecloak)
	pSequence.AddAI(pGreenAlert)
	# Done creating SequenceAI Sequence
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (35, 305)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pSequence)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
