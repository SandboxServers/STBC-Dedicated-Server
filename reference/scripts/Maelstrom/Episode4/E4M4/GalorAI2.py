import App
def CreateAI(pShip):
	#########################################
	# Creating CompoundAI AttackPlayer at (135, 135)
	import AI.Compound.BasicAttack
	pAttackPlayer = AI.Compound.BasicAttack.CreateAI(pShip, "player", Difficulty = 0.05, InaccurateTorps = 1)
	# Done creating CompoundAI AttackPlayer
	#########################################
	#########################################
	# Creating ConditionalAI IfAttackedByPlayer at (135, 94)
	## Conditions:
	#### Condition G1AttackedByPlayer
	pG1AttackedByPlayer = App.ConditionScript_Create("Conditions.ConditionAttackedBy", "ConditionAttackedBy", "Galor 1", "player", 0.2, 0.2, 120.0)
	#### Condition G2AttackedByPlayer
	pG2AttackedByPlayer = App.ConditionScript_Create("Conditions.ConditionAttackedBy", "ConditionAttackedBy", "Galor 2", "player", 0.2, 0.2, 120.0)
	## Evaluation function:
	def EvalFunc(bG1AttackedByPlayer, bG2AttackedByPlayer):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bG1AttackedByPlayer or bG2AttackedByPlayer):
			return ACTIVE
		else:
			return DORMANT
	## The ConditionalAI:
	pIfAttackedByPlayer = App.ConditionalAI_Create(pShip, "IfAttackedByPlayer")
	pIfAttackedByPlayer.SetInterruptable(1)
	pIfAttackedByPlayer.SetContainedAI(pAttackPlayer)
	pIfAttackedByPlayer.AddCondition(pG1AttackedByPlayer)
	pIfAttackedByPlayer.AddCondition(pG2AttackedByPlayer)
	pIfAttackedByPlayer.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI IfAttackedByPlayer
	#########################################
	#########################################
	# Creating CompoundAI AttackMavjop at (223, 94)
	import AI.Compound.BasicAttack
	pAttackMavjop = AI.Compound.BasicAttack.CreateAI(pShip,  "Mavjop", Difficulty = 0.05, InaccurateTorps = 1)
	# Done creating CompoundAI AttackMavjop
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (136, 24)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (168, 59)
	pPriorityList.AddAI(pIfAttackedByPlayer, 1)
	pPriorityList.AddAI(pAttackMavjop, 2)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (42, 24)
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
