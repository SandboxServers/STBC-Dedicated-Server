import App
def CreateAI(pShip):
	#########################################
	# Creating CompoundAI BasicAttackPlayer at (233, 128)
	import AI.Compound.BasicAttack
	pBasicAttackPlayer = AI.Compound.BasicAttack.CreateAI(pShip, "player", Easy_Difficulty = 0.43, Difficulty = 0.68, UseCloaking = 1, Hard_Difficulty = 0.92)
	# Done creating CompoundAI BasicAttackPlayer
	#########################################
	#########################################
	# Creating CompoundAI BasicAttackCardTargets at (348, 125)
	import AI.Compound.BasicAttack
	pBasicAttackCardTargets = AI.Compound.BasicAttack.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode6.E6M5.E6M5", "g_pCardTargets"), Easy_Difficulty = 0.38, Difficulty = 0.68, UseCloaking = 1, Hard_Difficulty = 0.91)
	# Done creating CompoundAI BasicAttackCardTargets
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (149, 234)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (298, 195)
	pPriorityList.AddAI(pBasicAttackPlayer, 1)
	pPriorityList.AddAI(pBasicAttackCardTargets, 2)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (62, 304)
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
