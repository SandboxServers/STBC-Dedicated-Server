import App
def CreateAI(pShip):
	#########################################
	# Creating CompoundAI BasicAttackStation at (66, 182)
	import AI.Compound.BasicAttack
	pBasicAttackStation = AI.Compound.BasicAttack.CreateAI(pShip, "Savoy Station", Easy_Difficulty = 0.42, Easy_ChooseSubsystemTargets = 0, Difficulty = 0.61, ChooseSubsystemTargets = 0, Hard_Difficulty = 0.75, Hard_ChooseSubsystemTargets = 0)
	# Done creating CompoundAI BasicAttackStation
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (63, 265)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pBasicAttackStation)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
