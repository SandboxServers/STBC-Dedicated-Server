import App

def CreateAI(pShip):
	#########################################
	# Creating CompoundAI AttackPlayer at (261, 169)
	import AI.Compound.BasicAttack
	pAttackPlayer = AI.Compound.BasicAttack.CreateAI(pShip, "player")
	# Done creating CompoundAI AttackPlayer
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (125, 187)
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
