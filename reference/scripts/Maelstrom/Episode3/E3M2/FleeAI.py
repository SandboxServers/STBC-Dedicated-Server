import App

def CreateAI(pShip, sWaypoint):

	#########################################
	# Creating PlainAI WarpOut at (168, 163)
	pWarpOut = App.PlainAI_Create(pShip, "WarpOut")
	pWarpOut.SetScriptModule("Warp")
	pWarpOut.SetInterruptable(1)
	# Done creating PlainAI WarpOut
	#########################################
	#########################################
	# Creating ConditionalAI IsNotInNebula at (169, 123)
	## Conditions:
	#### Condition InNebula
	pInNebula = App.ConditionScript_Create("Conditions.ConditionInNebula", "ConditionInNebula", pShip.GetName())
	## Evaluation function:
	def EvalFunc(bInNebula):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if not bInNebula:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pIsNotInNebula = App.ConditionalAI_Create(pShip, "IsNotInNebula")
	pIsNotInNebula.SetInterruptable(1)
	pIsNotInNebula.SetContainedAI(pWarpOut)
	pIsNotInNebula.AddCondition(pInNebula)
	pIsNotInNebula.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI IsNotInNebula
	#########################################
	#########################################
	# Creating PlainAI GoToStartPoint at (293, 123)
	pGoToStartPoint = App.PlainAI_Create(pShip, "GoToStartPoint")
	pGoToStartPoint.SetScriptModule("FollowWaypoints")
	pGoToStartPoint.SetInterruptable(1)
	pScript = pGoToStartPoint.GetScriptInstance()
	pScript.SetTargetWaypointName(sWaypoint)
	# Done creating PlainAI GoToStartPoint
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (220, 41)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (249, 72)
	pPriorityList.AddAI(pIsNotInNebula, 1)
	pPriorityList.AddAI(pGoToStartPoint, 2)
	# Done creating PriorityListAI PriorityList
	#########################################
	return pPriorityList
