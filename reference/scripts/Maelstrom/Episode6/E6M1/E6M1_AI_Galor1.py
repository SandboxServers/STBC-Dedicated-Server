import App
def CreateAI(pShip):
	#########################################
	# Creating CompoundAI BasicAttack2SF at (109, 107)
	import AI.Compound.BasicAttack
	pBasicAttack2SF = AI.Compound.BasicAttack.CreateAI(pShip, "San Francisco", Easy_Difficulty = 0.19, Difficulty = 0.3, InaccurateTorps = 1)
	# Done creating CompoundAI BasicAttack2SF
	#########################################
	#########################################
	# Creating CompoundAI BasicAttack2Player at (231, 107)
	import AI.Compound.BasicAttack
	pBasicAttack2Player = AI.Compound.BasicAttack.CreateAI(pShip, "player", Easy_Difficulty = 0.24, Difficulty = 0.59, InaccurateTorps = 1, Hard_Difficulty = 0.86)
	# Done creating CompoundAI BasicAttack2Player
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (91, 197)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (183, 174)
	pPriorityList.AddAI(pBasicAttack2SF, 1)
	pPriorityList.AddAI(pBasicAttack2Player, 2)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (46, 262)
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
