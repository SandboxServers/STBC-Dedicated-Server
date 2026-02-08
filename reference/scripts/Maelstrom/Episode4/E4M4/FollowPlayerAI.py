import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI Follow at (121, 148)
	pFollow = App.PlainAI_Create(pShip, "Follow")
	pFollow.SetScriptModule("FollowObject")
	pFollow.SetInterruptable(1)
	pScript = pFollow.GetScriptInstance()
	pScript.SetFollowObjectName("player")
	pScript.SetRoughDistances(100,150,200)
	# Done creating PlainAI Follow
	#########################################
	#########################################
	# Creating ConditionalAI PlayerInSameSet at (120, 102)
	## Conditions:
	#### Condition InSet
	pInSet = App.ConditionScript_Create("Conditions.ConditionAllInSameSet", "ConditionAllInSameSet", pShip.GetName(), "player")
	## Evaluation function:
	def EvalFunc(bInSet):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bInSet:
			# Player is in the same set as we are.
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pPlayerInSameSet = App.ConditionalAI_Create(pShip, "PlayerInSameSet")
	pPlayerInSameSet.SetInterruptable(1)
	pPlayerInSameSet.SetContainedAI(pFollow)
	pPlayerInSameSet.AddCondition(pInSet)
	pPlayerInSameSet.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI PlayerInSameSet
	#########################################
	#########################################
	# Creating CompoundAI FollowWarp at (209, 102)
	import AI.Compound.FollowThroughWarp
	pFollowWarp = AI.Compound.FollowThroughWarp.CreateAI(pShip, "player")
	# Done creating CompoundAI FollowWarp
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (120, 24)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (139, 65)
	pPriorityList.AddAI(pPlayerInSameSet, 1)
	pPriorityList.AddAI(pFollowWarp, 2)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (28, 23)
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
