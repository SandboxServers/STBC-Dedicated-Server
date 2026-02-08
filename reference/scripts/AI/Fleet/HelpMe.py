import App

def CreateAI(idShip):
	pShip = App.ShipClass_GetObjectByID(None, idShip)
	if not pShip:
		return None

	pPlayer = App.Game_GetCurrentPlayer()
	if not pPlayer:
		return None

	sPlayer = pPlayer.GetName()

	#########################################
	# Creating CompoundAI Defend at (154, 113)
	import AI.Compound.Defend
	pDefend = AI.Compound.Defend.CreateAI(pShip, sPlayer)
	# Done creating CompoundAI Defend
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (149, 181)
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
	# Creating ConditionalAI FleetHelpPlayer_TargetExists at (149, 233)
	## Conditions:
	#### Condition SameSet
	pSameSet = App.ConditionScript_Create("Conditions.ConditionAllInSameSet", "ConditionAllInSameSet", pShip.GetName(), sPlayer)
	## Evaluation function:
	def EvalFunc(bSameSet):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bSameSet:
			return ACTIVE
		return DONE
	## The ConditionalAI:
	pFleetHelpPlayer_TargetExists = App.ConditionalAI_Create(pShip, "FleetHelpPlayer_TargetExists")
	pFleetHelpPlayer_TargetExists.SetInterruptable(1)
	pFleetHelpPlayer_TargetExists.SetContainedAI(pAvoidObstacles)
	pFleetHelpPlayer_TargetExists.AddCondition(pSameSet)
	pFleetHelpPlayer_TargetExists.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI FleetHelpPlayer_TargetExists
	#########################################
	return pFleetHelpPlayer_TargetExists
