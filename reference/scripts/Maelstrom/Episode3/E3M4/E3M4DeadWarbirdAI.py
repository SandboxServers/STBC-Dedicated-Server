import App
def CreateAI(pShip):
	#########################################
	# Creating CompoundAI Fight at (288, 87)
	import AI.Compound.BasicAttack
	pFight = AI.Compound.BasicAttack.CreateAI(pShip, "Galor 1", "Galor 2", "Galor 3", "Keldon 1", Difficulty = 0.6)
	# Done creating CompoundAI Fight
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (285, 39)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pFight)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
