import App
def CreateAI(pShip, sPlacementName, pTargetGroup):


	#########################################
	# Creating CompoundAI BasicAttack2Targets at (87, 129)
	import AI.Compound.BasicAttack
	pBasicAttack2Targets = AI.Compound.BasicAttack.CreateAI(pShip, pTargetGroup, Easy_Difficulty = 0.21, Difficulty = 0.36, FollowTargetThroughWarp = 1, Hard_Difficulty = 0.66)
	# Done creating CompoundAI BasicAttack2Targets
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (56, 297)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pBasicAttack2Targets)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
