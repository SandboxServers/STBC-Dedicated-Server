import App
def CreateAI(pShip):
	#########################################
	# Creating CompoundAI BasicAttack2CardSecondTargets at (137, 100)
	import AI.Compound.BasicAttack
	pBasicAttack2CardSecondTargets = AI.Compound.BasicAttack.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode6.E6M5.E6M5", "g_pCardSecondTargets"), Easy_Difficulty = 0.35, Easy_UseCloaking = 1, Difficulty = 0.8, UseCloaking = 1, Hard_Difficulty = 1.0, Hard_UseCloaking = 1)
	# Done creating CompoundAI BasicAttack2CardSecondTargets
	#########################################
	#########################################
	# Creating CompoundAI BasicAttack2CardTargets at (272, 102)
	import AI.Compound.BasicAttack
	pBasicAttack2CardTargets = AI.Compound.BasicAttack.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode6.E6M5.E6M5", "g_pCardTargets"), Easy_Difficulty = 0.36, Easy_UseCloaking = 1, Difficulty = 0.76, UseCloaking = 1, Hard_Difficulty = 1.0, Hard_UseCloaking = 1)
	# Done creating CompoundAI BasicAttack2CardTargets
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (116, 197)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (225, 199)
	pPriorityList.AddAI(pBasicAttack2CardSecondTargets, 1)
	pPriorityList.AddAI(pBasicAttack2CardTargets, 2)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (25, 243)
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
