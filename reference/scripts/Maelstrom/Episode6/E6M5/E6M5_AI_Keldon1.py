import App
def CreateAI(pShip):
	#########################################
	# Creating CompoundAI BasicAttack4Player at (154, 152)
	import AI.Compound.BasicAttack
	pBasicAttack4Player = AI.Compound.BasicAttack.CreateAI(pShip, "player", Easy_Difficulty = 0.34, Difficulty = 0.82, Hard_Difficulty = 1.0)
	# Done creating CompoundAI BasicAttack4Player
	#########################################
	#########################################
	# Creating CompoundAI BasicAttackZhukov at (261, 151)
	import AI.Compound.BasicAttack
	pBasicAttackZhukov = AI.Compound.BasicAttack.CreateAI(pShip, "Zhukov", Easy_Difficulty = 0.37, Difficulty = 1.0, Hard_Difficulty = 1.0)
	# Done creating CompoundAI BasicAttackZhukov
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (112, 252)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (233, 226)
	pPriorityList.AddAI(pBasicAttack4Player, 1)
	pPriorityList.AddAI(pBasicAttackZhukov, 2)
	# Done creating PriorityListAI PriorityList
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
	pAvoidObstacles.SetContainedAI(pPriorityList)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
