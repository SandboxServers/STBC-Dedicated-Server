import App
def CreateAI(pShip):
	#########################################
	# Creating CompoundAI BasicAttackZhukov at (171, 109)
	import AI.Compound.BasicAttack
	pBasicAttackZhukov = AI.Compound.BasicAttack.CreateAI(pShip, "Zhukov", Easy_Difficulty = 0.48, Difficulty = 1.0, Hard_Difficulty = 1.0)
	# Done creating CompoundAI BasicAttackZhukov
	#########################################
	#########################################
	# Creating CompoundAI BasicAttackPlayer at (303, 103)
	import AI.Compound.BasicAttack
	pBasicAttackPlayer = AI.Compound.BasicAttack.CreateAI(pShip, "player", Easy_Difficulty = 0.39, Difficulty = 1.0, Hard_Difficulty = 1.0)
	# Done creating CompoundAI BasicAttackPlayer
	#########################################
	#########################################
	# Creating CompoundAI BasicAttackCardTargets at (430, 128)
	import AI.Compound.BasicAttack
	pBasicAttackCardTargets = AI.Compound.BasicAttack.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode6.E6M5.E6M5", "g_pCardTargets"), Easy_Difficulty = 0.43, Difficulty = 0.85, Hard_Difficulty = 1.0)
	# Done creating CompoundAI BasicAttackCardTargets
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (202, 210)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (298, 195)
	pPriorityList.AddAI(pBasicAttackZhukov, 1)
	pPriorityList.AddAI(pBasicAttackPlayer, 2)
	pPriorityList.AddAI(pBasicAttackCardTargets, 3)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (83, 249)
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
