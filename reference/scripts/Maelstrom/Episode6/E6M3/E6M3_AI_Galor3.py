import App
def CreateAI(pShip):
	#########################################
	# Creating CompoundAI BasicAttackFeds at (172, 56)
	import AI.Compound.BasicAttack
	pBasicAttackFeds = AI.Compound.BasicAttack.CreateAI(pShip, "Devore", Easy_Difficulty = 0.16, Difficulty = 0.41, SmartShields = 1, Hard_Difficulty = 0.64)
	# Done creating CompoundAI BasicAttackFeds
	#########################################
	#########################################
	# Creating CompoundAI BasicAttackSavoy3GalorTargets at (293, 76)
	import AI.Compound.BasicAttack
	pBasicAttackSavoy3GalorTargets = AI.Compound.BasicAttack.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode6.E6M3.E6M3", "g_pSavoy3GalorTargets"), Easy_Difficulty = 0.17, Difficulty = 0.52, SmartShields = 1, Hard_Difficulty = 0.85)
	# Done creating CompoundAI BasicAttackSavoy3GalorTargets
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (109, 187)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (187, 130)
	pPriorityList.AddAI(pBasicAttackFeds, 1)
	pPriorityList.AddAI(pBasicAttackSavoy3GalorTargets, 2)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating ConditionalAI FedsClose at (65, 242)
	## Conditions:
	#### Condition FedsInRange150
	pFedsInRange150 = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 850, pShip.GetName(), App.ObjectGroup_FromModule("Maelstrom.Episode6.E6M3.E6M3", "g_pSavoy3GalorTargets"))
	## Evaluation function:
	def EvalFunc(bFedsInRange150):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bFedsInRange150):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pFedsClose = App.ConditionalAI_Create(pShip, "FedsClose")
	pFedsClose.SetInterruptable(1)
	pFedsClose.SetContainedAI(pPriorityList)
	pFedsClose.AddCondition(pFedsInRange150)
	pFedsClose.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI FedsClose
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (18, 306)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pFedsClose)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
