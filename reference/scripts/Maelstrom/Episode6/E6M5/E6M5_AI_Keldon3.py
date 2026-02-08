import App
def CreateAI(pShip):
	#########################################
	# Creating CompoundAI BasicAttackPlayer at (248, 50)
	import AI.Compound.BasicAttack
	pBasicAttackPlayer = AI.Compound.BasicAttack.CreateAI(pShip, "player", Easy_Difficulty = 0.29, Difficulty = 0.5, Hard_Difficulty = 0.81)
	# Done creating CompoundAI BasicAttackPlayer
	#########################################
	#########################################
	# Creating CompoundAI BasicAttackCardTargets at (343, 112)
	import AI.Compound.BasicAttack
	pBasicAttackCardTargets = AI.Compound.BasicAttack.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode6.E6M5.E6M5", "g_pCardTargets"), Easy_Difficulty = 0.26, Difficulty = 0.54, Hard_Difficulty = 0.79)
	# Done creating CompoundAI BasicAttackCardTargets
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (141, 180)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (262, 184)
	pPriorityList.AddAI(pBasicAttackPlayer, 1)
	pPriorityList.AddAI(pBasicAttackCardTargets, 2)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (141, 233)
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
