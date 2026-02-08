import App
def CreateAI(pShip):
	#########################################
	# Creating CompoundAI Attack_Player at (180, 70)
	import AI.Compound.BasicAttack
	pAttack_Player = AI.Compound.BasicAttack.CreateAI(pShip, "player", WarpOutBeforeDying = 1)
	# Flag WarpOutBeforeDying = 1
	# Done creating CompoundAI Attack_Player
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (78, 66)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pAttack_Player)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
