import App
def CreateAI(pShip):
	#########################################
	# Creating CompoundAI Attack at (288, 38)
	import AI.Compound.BasicAttack
	pAttack = AI.Compound.BasicAttack.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode7.E7M1.E7M1", "pFriendlies"), Difficulty = 1.0)
	# Done creating CompoundAI Attack
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (190, 58)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pAttack)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
