import App

def Done():
	pass

def CreateAI(pShip):

	#########################################
	# Creating PlainAI WarpOut at (247, 230)
	pWarpOut = App.PlainAI_Create(pShip, "WarpOut")
	pWarpOut.SetScriptModule("Warp")
	pWarpOut.SetInterruptable(1)
	# Done creating PlainAI WarpOut
	#########################################
	#########################################
	# Creating ConditionalAI IfShipyardDestroyed at (206, 194)
	## Conditions:
	#### Condition ShipyardDestroyed
	pShipyardDestroyed = App.ConditionScript_Create("Conditions.ConditionDestroyed", "ConditionDestroyed", "Cardassian Shipyard")
	## Evaluation function:
	def EvalFunc(bShipyardDestroyed):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bShipyardDestroyed:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pIfShipyardDestroyed = App.ConditionalAI_Create(pShip, "IfShipyardDestroyed")
	pIfShipyardDestroyed.SetInterruptable(1)
	pIfShipyardDestroyed.SetContainedAI(pWarpOut)
	pIfShipyardDestroyed.AddCondition(pShipyardDestroyed)
	pIfShipyardDestroyed.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI IfShipyardDestroyed
	#########################################
	#########################################
	# Creating CompoundAI AttackPlayerNormal at (265, 155)
	import AI.Compound.BasicAttack
	pAttackPlayerNormal = AI.Compound.BasicAttack.CreateAI(pShip, "USS Enterprise", Difficulty = 0.25, InaccurateTorps = 1)
	# Done creating CompoundAI AttackPlayerNormal
	#########################################
	#########################################
	# Creating ConditionalAI PlayerAttacked at (224, 121)
	## Conditions:
	#### Condition AttackedByPlayer
	pAttackedByPlayer = App.ConditionScript_Create("Conditions.ConditionAttackedBy", "ConditionAttackedBy", pShip.GetName(), "player", 0, 0, 0, 30.0)
	## Evaluation function:
	def EvalFunc(bAttackedByPlayer):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bAttackedByPlayer:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pPlayerAttacked = App.ConditionalAI_Create(pShip, "PlayerAttacked")
	pPlayerAttacked.SetInterruptable(1)
	pPlayerAttacked.SetContainedAI(pAttackPlayerNormal)
	pPlayerAttacked.AddCondition(pAttackedByPlayer)
	pPlayerAttacked.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI PlayerAttacked
	#########################################
	#########################################
	# Creating CompoundAI AttackEnterpriseNormal at (239, 79)
	import AI.Compound.BasicAttack
	pAttackEnterpriseNormal = AI.Compound.BasicAttack.CreateAI(pShip, "USS Enterprise", Difficulty = 0.25, InaccurateTorps = 1, SmartShields = 1)
	# Done creating CompoundAI AttackEnterpriseNormal
	#########################################
	#########################################
	# Creating PlainAI Stay at (254, 46)
	pStay = App.PlainAI_Create(pShip, "Stay")
	pStay.SetScriptModule("Stay")
	pStay.SetInterruptable(1)
	# Done creating PlainAI Stay
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (108, 11)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (197, 19)
	pPriorityList.AddAI(pIfShipyardDestroyed, 1)
	pPriorityList.AddAI(pPlayerAttacked, 2)
	pPriorityList.AddAI(pAttackEnterpriseNormal, 3)
	pPriorityList.AddAI(pStay, 4)
	# Done creating PriorityListAI PriorityList
	#########################################

	#########################################
	# Creating PreprocessingAI AvoidObstacles at (24, 31)
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
