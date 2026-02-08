import App
def CreateAI(pShip):
	#########################################
	# Creating CompoundAI BasicAttackZuhkov at (126, 121)
	import AI.Compound.BasicAttack
	pBasicAttackZuhkov = AI.Compound.BasicAttack.CreateAI(pShip, "Zhukov", Easy_Difficulty = 0.37, Difficulty = 1.0, Hard_Difficulty = 1.0)
	# Done creating CompoundAI BasicAttackZuhkov
	#########################################
	#########################################
	# Creating CompoundAI BasicAttackCardTargets_2 at (247, 151)
	import AI.Compound.BasicAttack
	pBasicAttackCardTargets_2 = AI.Compound.BasicAttack.CreateAI(pShip, "Zhukov", Easy_Difficulty = 0.33, Difficulty = 0.79, Hard_Difficulty = 1.0)
	# Done creating CompoundAI BasicAttackCardTargets_2
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (47, 216)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (192, 223)
	pPriorityList.AddAI(pBasicAttackZuhkov, 1)
	pPriorityList.AddAI(pBasicAttackCardTargets_2, 2)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (38, 283)
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
