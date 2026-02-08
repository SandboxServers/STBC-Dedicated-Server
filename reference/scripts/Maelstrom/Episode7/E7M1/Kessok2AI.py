import App
def CreateAI(pShip):
	#########################################
	# Creating CompoundAI Attack at (157, 17)
	import AI.Compound.BasicAttack
	pAttack = AI.Compound.BasicAttack.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode7.E7M1.E7M1", "pFriendlies"), Difficulty = 0.9, SmartPhasers = 1, UseCloaking = 1, WarpOutBeforeDying = 1)
	# Done creating CompoundAI Attack
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (51, 37)
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
