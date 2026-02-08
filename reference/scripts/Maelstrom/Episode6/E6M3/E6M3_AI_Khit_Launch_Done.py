import App
def CreateAI(pShip):
	#########################################
	# Creating CompoundAI BasicAttack4Savoy1Transports at (138, 129)
	import AI.Compound.BasicAttack
	pBasicAttack4Savoy1Transports = AI.Compound.BasicAttack.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode6.E6M3.E6M3", "g_pSavoy1Transports"), Difficulty = 0.01)
	# Done creating CompoundAI BasicAttack4Savoy1Transports
	#########################################
	#########################################
	# Creating CompoundAI BasicAttack4Savoy1Tragets at (237, 127)
	import AI.Compound.BasicAttack
	pBasicAttack4Savoy1Tragets = AI.Compound.BasicAttack.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode6.E6M3.E6M3", "g_pSavoy1FedsTargets"), Difficulty = 0.75)
	# Done creating CompoundAI BasicAttack4Savoy1Tragets
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (45, 241)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (174, 217)
	pPriorityList.AddAI(pBasicAttack4Savoy1Transports, 1)
	pPriorityList.AddAI(pBasicAttack4Savoy1Tragets, 2)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (37, 301)
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
