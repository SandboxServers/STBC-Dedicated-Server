import App
def CreateAI(pShip):
	#########################################
	# Creating CompoundAI AttackPlayer at (297, 87)
	import AI.Compound.BasicAttack
	pAttackPlayer = AI.Compound.BasicAttack.CreateAI(pShip, "player", TargetSubsystems = [ (App.CT_IMPULSE_ENGINE_SUBSYSTEM, 1.0), (App.CT_WARP_ENGINE_SUBSYSTEM, 0.5) ], Difficulty = 1.0)
	# Done creating CompoundAI AttackPlayer
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (209, 107)
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
