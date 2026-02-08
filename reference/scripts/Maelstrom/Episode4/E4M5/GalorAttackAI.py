import App
def Done():
	pass
def CreateAI(pShip, pcTarget):


	#########################################
	# Creating PlainAI WarpOut at (258, 340)
	pWarpOut = App.PlainAI_Create(pShip, "WarpOut")
	pWarpOut.SetScriptModule("Warp")
	pWarpOut.SetInterruptable(1)
	# Done creating PlainAI WarpOut
	#########################################
	#########################################
	# Creating ConditionalAI If_Starbase_Destroyed at (217, 304)
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
	pIf_Starbase_Destroyed = App.ConditionalAI_Create(pShip, "If_Starbase_Destroyed")
	pIf_Starbase_Destroyed.SetInterruptable(1)
	pIf_Starbase_Destroyed.SetContainedAI(pWarpOut)
	pIf_Starbase_Destroyed.AddCondition(pShipyardDestroyed)
	pIf_Starbase_Destroyed.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI If_Starbase_Destroyed
	#########################################
	#########################################
	# Creating CompoundAI AttackPlayerNormal at (274, 261)
	import AI.Compound.BasicAttack
	pAttackPlayerNormal = AI.Compound.BasicAttack.CreateAI(pShip, "player", Difficulty = 0.15, InaccurateTorps = 1)
	# Done creating CompoundAI AttackPlayerNormal
	#########################################
	#########################################
	# Creating ConditionalAI AttackedByPlayer at (233, 225)
	## Conditions:
	#### Condition PlayerAttacked
	pPlayerAttacked = App.ConditionScript_Create("Conditions.ConditionAttackedBy", "ConditionAttackedBy", pShip.GetName(), "player", 0, 0, 0, 30.0)
	## Evaluation function:
	def EvalFunc(bPlayerAttacked):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bPlayerAttacked:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pAttackedByPlayer = App.ConditionalAI_Create(pShip, "AttackedByPlayer")
	pAttackedByPlayer.SetInterruptable(1)
	pAttackedByPlayer.SetContainedAI(pAttackPlayerNormal)
	pAttackedByPlayer.AddCondition(pPlayerAttacked)
	pAttackedByPlayer.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI AttackedByPlayer
	#########################################
	#########################################
	# Creating CompoundAI AttackTarget at (250, 182)
	import AI.Compound.BasicAttack
	pAttackTarget = AI.Compound.BasicAttack.CreateAI(pShip, pcTarget, Difficulty = 0.05, InaccurateTorps = 1)
	# Done creating CompoundAI AttackTarget
	#########################################
	#########################################
	# Creating CompoundAI AttackEnterprise at (264, 150)
	import AI.Compound.BasicAttack
	pAttackEnterprise = AI.Compound.BasicAttack.CreateAI(pShip, "USS Enterprise", Difficulty = 0.1, SmartShields = 1)
	# Done creating CompoundAI AttackEnterprise
	#########################################
	#########################################
	# Creating PlainAI Circle_the_Starbase at (306, 118)
	pCircle_the_Starbase = App.PlainAI_Create(pShip, "Circle_the_Starbase")
	pCircle_the_Starbase.SetScriptModule("IntelligentCircleObject")
	pCircle_the_Starbase.SetInterruptable(1)
	pScript = pCircle_the_Starbase.GetScriptInstance()
	pScript.SetFollowObjectName("Cardassian Shipyard")
	pScript.SetRoughDistances(100, 150)
	pScript.SetCircleSpeed(3)
	# Done creating PlainAI Circle_the_Starbase
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (209, 57)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (209, 124)
	pPriorityList.AddAI(pIf_Starbase_Destroyed, 1)
	pPriorityList.AddAI(pAttackedByPlayer, 2)
	pPriorityList.AddAI(pAttackTarget, 3)
	pPriorityList.AddAI(pAttackEnterprise, 4)
	pPriorityList.AddAI(pCircle_the_Starbase, 5)
	# Done creating PriorityListAI PriorityList
	#########################################

	#########################################
	# Creating PreprocessingAI AvoidObstacles at (210, 18)
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
