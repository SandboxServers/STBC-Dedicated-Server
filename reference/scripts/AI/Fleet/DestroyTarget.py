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
	# Creating CompoundAI Attack at (153, 117)
	import AI.Compound.BasicAttack
	pAttack = AI.Compound.BasicAttack.CreateAI(pShip, sTarget)
	# Done creating CompoundAI Attack
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (159, 179)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pAttack)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	#########################################
	# Creating ConditionalAI FleetDestroy_TargetExists at (159, 234)
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
	pFleetDestroy_TargetExists = App.ConditionalAI_Create(pShip, "FleetDestroy_TargetExists")
	pFleetDestroy_TargetExists.SetInterruptable(1)
	pFleetDestroy_TargetExists.SetContainedAI(pAvoidObstacles)
	pFleetDestroy_TargetExists.AddCondition(pSameSet)
	pFleetDestroy_TargetExists.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI FleetDestroy_TargetExists
	#########################################
	return pFleetDestroy_TargetExists
