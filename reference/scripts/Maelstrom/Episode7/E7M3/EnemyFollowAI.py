import App
def CreateAI(pShip):
	#########################################
	# Creating CompoundAI FollowPlayer at (442, 153)
	import AI.Compound.FollowThroughWarp
	pFollowPlayer = AI.Compound.FollowThroughWarp.CreateAI(pShip, "player")
	# Done creating CompoundAI FollowPlayer
	#########################################
	#########################################
	# Creating ConditionalAI IfWarpAble at (340, 173)
	## Conditions:
	#### Condition WarpDisabled
	pWarpDisabled = App.ConditionScript_Create("Conditions.ConditionSystemDisabled", "ConditionSystemDisabled", pShip.GetName(), App.CT_WARP_ENGINE_SUBSYSTEM)
	#### Condition WarpDestroyed
	pWarpDestroyed = App.ConditionScript_Create("Conditions.ConditionSystemDestroyed", "ConditionSystemDestroyed", pShip.GetName(), App.CT_WARP_ENGINE_SUBSYSTEM)
	## Evaluation function:
	def EvalFunc(bWarpDisabled, bWarpDestroyed):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bWarpDisabled or bWarpDestroyed:
			return DORMANT
		return ACTIVE
	## The ConditionalAI:
	pIfWarpAble = App.ConditionalAI_Create(pShip, "IfWarpAble")
	pIfWarpAble.SetInterruptable(1)
	pIfWarpAble.SetContainedAI(pFollowPlayer)
	pIfWarpAble.AddCondition(pWarpDisabled)
	pIfWarpAble.AddCondition(pWarpDestroyed)
	pIfWarpAble.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI IfWarpAble
	#########################################
	#########################################
	# Creating CompoundAI Attack at (356, 128)
	import Ai.Compound.BasicAttack
	pAttack = Ai.Compound.BasicAttack.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode7.E7M3.E7M3", "pFriendlies"), Difficulty = 0.6, UseCloaking = 1)
	# Done creating CompoundAI Attack
	#########################################
	#########################################
	# Creating PlainAI Stay at (372, 91)
	pStay = App.PlainAI_Create(pShip, "Stay")
	pStay.SetScriptModule("Stay")
	pStay.SetInterruptable(1)
	# Done creating PlainAI Stay
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (167, 57)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (331, 65)
	pPriorityList.AddAI(pIfWarpAble, 1)
	pPriorityList.AddAI(pAttack, 2)
	pPriorityList.AddAI(pStay, 3)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (81, 77)
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
