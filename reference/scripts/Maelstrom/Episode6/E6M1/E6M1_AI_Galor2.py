import App
def CreateAI(pShip):
	#########################################
	# Creating CompoundAI BasicAttack2Player at (256, 117)
	import AI.Compound.BasicAttack
	pBasicAttack2Player = AI.Compound.BasicAttack.CreateAI(pShip, "player", Easy_Difficulty = 0.2, Difficulty = 0.53, DisableBeforeDestroy = 1, InaccurateTorps = 1, Hard_Difficulty = 0.82)
	# Done creating CompoundAI BasicAttack2Player
	#########################################
	#########################################
	# Creating CompoundAI BasicAttack2SF at (378, 115)
	import AI.Compound.BasicAttack
	pBasicAttack2SF = AI.Compound.BasicAttack.CreateAI(pShip, "San Francisco", Easy_Difficulty = 0.13, Difficulty = 0.35, DisableBeforeDestroy = 1, InaccurateTorps = 1)
	# Done creating CompoundAI BasicAttack2SF
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (185, 211)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (308, 219)
	pPriorityList.AddAI(pBasicAttack2Player, 1)
	pPriorityList.AddAI(pBasicAttack2SF, 2)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (75, 249)
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
