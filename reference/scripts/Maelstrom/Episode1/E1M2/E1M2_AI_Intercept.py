import App

def CreateAI(pShip, sTargetName):

	#########################################
	# Creating PlainAI Intercept at (68, 118)
	pIntercept = App.PlainAI_Create(pShip, "Intercept")
	pIntercept.SetScriptModule("Intercept")
	pIntercept.SetInterruptable(1)
	pScript = pIntercept.GetScriptInstance()
	pScript.SetTargetObjectName(sTargetName)
	pScript.SetInterceptDistance(fDistance = 0)
	pScript.SetAddObjectRadius(bUseRadius = 1)
	# Done creating PlainAI Intercept
	#########################################
	#########################################
	# Creating ConditionalAI NotCloseToTarget at (67, 170)
	## Conditions:
	#### Condition CloseToTarget
	pCloseToTarget = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 80, pShip.GetName(), sTargetName)
	#### Condition TractorBeamOn
	pTractorBeamOn = App.ConditionScript_Create("Conditions.ConditionFiringTractorBeam", "ConditionFiringTractorBeam", pShip)
	## Evaluation function:
	def EvalFunc(bCloseToTarget, bTractorBeamOn):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bCloseToTarget or bTractorBeamOn:
			return DORMANT
		return ACTIVE
	## The ConditionalAI:
	pNotCloseToTarget = App.ConditionalAI_Create(pShip, "NotCloseToTarget")
	pNotCloseToTarget.SetInterruptable(1)
	pNotCloseToTarget.SetContainedAI(pIntercept)
	pNotCloseToTarget.AddCondition(pCloseToTarget)
	pNotCloseToTarget.AddCondition(pTractorBeamOn)
	pNotCloseToTarget.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI NotCloseToTarget
	#########################################
	#########################################
	# Creating PlainAI FaceTowardTarget at (170, 162)
	pFaceTowardTarget = App.PlainAI_Create(pShip, "FaceTowardTarget")
	pFaceTowardTarget.SetScriptModule("TurnToOrientation")
	pFaceTowardTarget.SetInterruptable(1)
	pScript = pFaceTowardTarget.GetScriptInstance()
	pScript.SetObjectName(sTargetName)
	pScript.SetPrimaryDirection(vDirection = App.TGPoint3_GetModelForward())
	# Done creating PlainAI FaceTowardTarget
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (40, 243)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (153, 242)
	pPriorityList.AddAI(pNotCloseToTarget, 1)
	pPriorityList.AddAI(pFaceTowardTarget, 2)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (41, 304)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pPriorityList)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
