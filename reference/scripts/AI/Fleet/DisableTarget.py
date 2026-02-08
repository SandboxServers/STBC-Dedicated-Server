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

	lTargetSubsystems = [
		(App.CT_IMPULSE_ENGINE_SUBSYSTEM, 2),
		(App.CT_WARP_ENGINE_SUBSYSTEM, 2),
		(App.CT_WEAPON_SYSTEM, 1),
		(App.CT_CLOAKING_SUBSYSTEM, 0) ]

	#########################################
	# Creating CompoundAI Attack at (150, 121)
	import AI.Compound.BasicAttack
	pAttack = AI.Compound.BasicAttack.CreateAI(pShip, sTarget, TargetSubsystems = lTargetSubsystems, Difficulty = 1.0, DisableOnly = 1)
	# Done creating CompoundAI Attack
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (150, 178)
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
	# Creating ConditionalAI FleetDisable_TargetExists at (149, 233)
	## Conditions:
	#### Condition SameSet
	pSameSet = App.ConditionScript_Create("Conditions.ConditionAllInSameSet", "ConditionAllInSameSet", pShip.GetName(), sTarget, sPlayer)
	#### Condition TargetDisabled
	pTargetDisabled = App.ConditionScript_Create("Conditions.ConditionShipDisabled", "ConditionShipDisabled", sTarget)
	## Evaluation function:
	def EvalFunc(bSameSet, bTargetDisabled):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bSameSet:
			if bTargetDisabled:
				return DORMANT
			return ACTIVE
		return DONE
	## The ConditionalAI:
	pFleetDisable_TargetExists = App.ConditionalAI_Create(pShip, "FleetDisable_TargetExists")
	pFleetDisable_TargetExists.SetInterruptable(1)
	pFleetDisable_TargetExists.SetContainedAI(pAvoidObstacles)
	pFleetDisable_TargetExists.AddCondition(pSameSet)
	pFleetDisable_TargetExists.AddCondition(pTargetDisabled)
	pFleetDisable_TargetExists.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI FleetDisable_TargetExists
	#########################################
	return pFleetDisable_TargetExists
