import App
def CreateAI(pShip):
	#########################################
	# Creating CompoundAI BasicAttack2Player at (272, 102)
	import AI.Compound.BasicAttack
	pBasicAttack2Player = AI.Compound.BasicAttack.CreateAI(pShip, "player", Easy_Difficulty = 0.35, Easy_UseCloaking = 1, Difficulty = 0.9, UseCloaking = 1, Hard_Difficulty = 1.0, Hard_UseCloaking = 1)
	# Done creating CompoundAI BasicAttack2Player
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (175, 184)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pBasicAttack2Player)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
