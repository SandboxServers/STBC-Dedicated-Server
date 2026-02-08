import App

def CreateAI(pShip, sFollowShipName):
	#########################################
	# Creating CompoundAI AttackPlayer at (82, 123)
	import AI.Compound.BasicAttack
	pAttackPlayer = AI.Compound.BasicAttack.CreateAI(pShip, "player")
	# Done creating CompoundAI AttackPlayer
	#########################################
	#########################################
	# Creating ConditionalAI Conditional at (82, 91)
	## Conditions:
	#### Condition InRange
	pInRange = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 100, "player", App.ObjectGroup_FromModule("Maelstrom.Episode5.E5M4.E5M4", "pEnemies"))
	## Evaluation function:
	def EvalFunc(bInRange):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bInRange:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pConditional = App.ConditionalAI_Create(pShip, "Conditional")
	pConditional.SetInterruptable(1)
	pConditional.SetContainedAI(pAttackPlayer)
	pConditional.AddCondition(pInRange)
	pConditional.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI Conditional
	#########################################
	#########################################
	# Creating PlainAI Follow at (167, 124)
	pFollow = App.PlainAI_Create(pShip, "Follow")
	pFollow.SetScriptModule("FollowObject")
	pFollow.SetInterruptable(1)
	pScript = pFollow.GetScriptInstance()
	pScript.SetFollowObjectName(sFollowShipName)
	# Done creating PlainAI Follow
	#########################################
	#########################################
	# Creating ConditionalAI Conditional_2 at (167, 91)
	## Conditions:
	#### Condition InSet
	pInSet = App.ConditionScript_Create("Conditions.ConditionAllInSameSet", "ConditionAllInSameSet", pShip.GetName(), sFollowShipName)
	## Evaluation function:
	def EvalFunc(bInSet):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bInSet:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pConditional_2 = App.ConditionalAI_Create(pShip, "Conditional_2")
	pConditional_2.SetInterruptable(1)
	pConditional_2.SetContainedAI(pFollow)
	pConditional_2.AddCondition(pInSet)
	pConditional_2.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI Conditional_2
	#########################################
	#########################################
	# Creating CompoundAI FollowThroughWarp at (274, 87)
	import AI.Compound.FollowThroughWarp
	pFollowThroughWarp = AI.Compound.FollowThroughWarp.CreateAI(pShip, sFollowShipName)
	# Done creating CompoundAI FollowThroughWarp
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (91, 14)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (193, 25)
	pPriorityList.AddAI(pConditional, 1)
	pPriorityList.AddAI(pConditional_2, 2)
	pPriorityList.AddAI(pFollowThroughWarp, 3)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (5, 14)
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
