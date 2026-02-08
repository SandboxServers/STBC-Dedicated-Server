import App
def CreateAI(pShip, pTargetGroup):

	#########################################
	# Creating PlainAI WarpToDeepSpace at (408, 40)
	pWarpToDeepSpace = App.PlainAI_Create(pShip, "WarpToDeepSpace")
	pWarpToDeepSpace.SetScriptModule("Warp")
	pWarpToDeepSpace.SetInterruptable(1)
	pScript = pWarpToDeepSpace.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.DeepSpace.DeepSpace")
	# Done creating PlainAI WarpToDeepSpace
	#########################################
	#########################################
	# Creating ConditionalAI TakingHullDamage at (245, 146)
	## Conditions:
	#### Condition HullTakingDamage
	pHullTakingDamage = App.ConditionScript_Create("Conditions.ConditionAttackedBy", "ConditionAttackedBy", pShip.GetName(),  "player", 2, 0.3, 99)
	## Evaluation function:
	def EvalFunc(bHullTakingDamage):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bHullTakingDamage):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pTakingHullDamage = App.ConditionalAI_Create(pShip, "TakingHullDamage")
	pTakingHullDamage.SetInterruptable(1)
	pTakingHullDamage.SetContainedAI(pWarpToDeepSpace)
	pTakingHullDamage.AddCondition(pHullTakingDamage)
	pTakingHullDamage.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI TakingHullDamage
	#########################################
	#########################################
	# Creating CompoundAI BasicAttack2Targets at (399, 218)
	import AI.Compound.BasicAttack
	pBasicAttack2Targets = AI.Compound.BasicAttack.CreateAI(pShip, pTargetGroup, Easy_Difficulty = 0.26, Difficulty = 1.0, Hard_Difficulty = 1.0)
	# Done creating CompoundAI BasicAttack2Targets
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (165, 319)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (310, 317)
	pPriorityList.AddAI(pTakingHullDamage, 1)
	pPriorityList.AddAI(pBasicAttack2Targets, 2)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (42, 357)
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
