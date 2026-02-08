import App

def CreateAI(idShip, idTarget):
	pShip = App.ShipClass_GetObjectByID(None, idShip)
	pTarget = App.ShipClass_GetObjectByID(None, idTarget)

	if (not pShip) or (not pTarget):
		return None

	sTarget = pTarget.GetName()

	pPlayer = App.Game_GetCurrentPlayer()
	if not pPlayer:
		return None
	sPlayer = pPlayer.GetName()

	#########################################
	# Creating CompoundAI Defend at (96, 128)
	import AI.Compound.Defend
	pDefend = AI.Compound.Defend.CreateAI(pShip, sTarget)
	# Done creating CompoundAI Defend
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (97, 182)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pDefend)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	#########################################
	# Creating ConditionalAI FleetDefend_TargetExists at (95, 231)
	## Conditions:
	#### Condition SameSet
	pSameSet = App.ConditionScript_Create("Conditions.ConditionAllInSameSet", "ConditionAllInSameSet", pShip.GetName(), sTarget, sPlayer)
	## Evaluation function:
	def EvalFunc(bSameSet):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bSameSet:
			return ACTIVE
		return DONE
	## The ConditionalAI:
	pFleetDefend_TargetExists = App.ConditionalAI_Create(pShip, "FleetDefend_TargetExists")
	pFleetDefend_TargetExists.SetInterruptable(1)
	pFleetDefend_TargetExists.SetContainedAI(pAvoidObstacles)
	pFleetDefend_TargetExists.AddCondition(pSameSet)
	pFleetDefend_TargetExists.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI FleetDefend_TargetExists
	#########################################
	return pFleetDefend_TargetExists
