import App
def CreateAI(pShip, pTargetGroup):

	#########################################
	# Creating CompoundAI BasicAttackZhukov at (50, 50)
	import AI.Compound.BasicAttack
	pBasicAttackZhukov = AI.Compound.BasicAttack.CreateAI(pShip, "Zhukov", Easy_Difficulty = 0.33, Difficulty = 1.0, Hard_Difficulty = 1.0)
	# Done creating CompoundAI BasicAttackZhukov
	#########################################
	#########################################
	# Creating CompoundAI BasicAttackCardTargets at (215, 67)
	import AI.Compound.BasicAttack
	pBasicAttackCardTargets = AI.Compound.BasicAttack.CreateAI(pShip, pTargetGroup, Easy_Difficulty = 0.28, Difficulty = 0.67, Hard_Difficulty = 1.0)
	# Done creating CompoundAI BasicAttackCardTargets
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (67, 185)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (159, 138)
	pPriorityList.AddAI(pBasicAttackZhukov, 1)
	pPriorityList.AddAI(pBasicAttackCardTargets, 2)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating ConditionalAI AnyFedsInSet at (105, 239)
	## Conditions:
	#### Condition FedsInSet
	pFedsInSet = App.ConditionScript_Create("Conditions.ConditionAnyInSameSet", "ConditionAnyInSameSet", pShip.GetName(), "Khitomer", "player", "Devore", "San Francisco", "Zhukov", "Venture")
	## Evaluation function:
	def EvalFunc(bFedsInSet):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bFedsInSet):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pAnyFedsInSet = App.ConditionalAI_Create(pShip, "AnyFedsInSet")
	pAnyFedsInSet.SetInterruptable(1)
	pAnyFedsInSet.SetContainedAI(pPriorityList)
	pAnyFedsInSet.AddCondition(pFedsInSet)
	pAnyFedsInSet.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI AnyFedsInSet
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (112, 314)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pAnyFedsInSet)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
