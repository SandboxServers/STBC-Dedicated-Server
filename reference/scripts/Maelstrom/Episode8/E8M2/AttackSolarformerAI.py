import App
def CreateAI(pShip):
	#########################################
	# Creating CompoundAI AttackSolarformer at (297, 87)
	import AI.Compound.BasicAttack
	pAttackSolarformer = AI.Compound.BasicAttack.CreateAI(pShip, "Solarformer", Difficulty = .75)
	# Done creating CompoundAI AttackSolarformer
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
	pAvoidObstacles.SetContainedAI(pAttackSolarformer)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
