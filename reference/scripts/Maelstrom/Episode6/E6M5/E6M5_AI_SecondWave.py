import App
def CreateAI(pShip):
	#########################################
	# Creating CompoundAI BasicAttackZhukov at (50, 50)
	import AI.Compound.BasicAttack
	pBasicAttackZhukov = AI.Compound.BasicAttack.CreateAI(pShip, "Zhukov", Easy_Difficulty = 1.0, Difficulty = 1.0, Hard_Difficulty = 1.0)
	# Done creating CompoundAI BasicAttackZhukov
	#########################################
	#########################################
	# Creating CompoundAI BasicAttack2ndTargets at (189, 57)
	import AI.Compound.BasicAttack
	pBasicAttack2ndTargets = AI.Compound.BasicAttack.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode6.E6M5.E6M5", "g_pCardSecondTargets"), Easy_Difficulty = 0.37, Easy_UseCloaking = 1, Difficulty = 0.76, UseCloaking = 1, Hard_Difficulty = 1.0, Hard_UseCloaking = 1)
	# Done creating CompoundAI BasicAttack2ndTargets
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (85, 171)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (155, 137)
	pPriorityList.AddAI(pBasicAttackZhukov, 1)
	pPriorityList.AddAI(pBasicAttack2ndTargets, 2)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (127, 220)
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
