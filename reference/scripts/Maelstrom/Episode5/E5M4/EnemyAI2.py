import App

def CreateAI(pShip):
	#########################################
	# Creating CompoundAI AttackPlayer at (195, 50)
	import AI.Compound.BasicAttack
	pAttackPlayer = AI.Compound.BasicAttack.CreateAI(pShip, "player", Difficulty = 0.65, FollowTargetThroughWarp = 1, FollowToSB12 = 0, WarpOutBeforeDying = 0)
	# Done creating CompoundAI AttackPlayer
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (92, 52)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pAttackPlayer)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
