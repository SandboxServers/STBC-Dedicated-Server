import App
def CreateAI(pShip):
	#########################################
	# Creating CompoundAI BasicAttack at (208, 50)
	import AI.Compound.BasicAttack
	pBasicAttack = AI.Compound.BasicAttack.CreateAI(pShip, "Chairo", Difficulty = 1.0, AvoidTorps = 0, ChooseSubsystemTargets = 0, DisableBeforeDestroy = 1, InaccurateTorps = 0, SmartShields = 0)
	# Done creating CompoundAI BasicAttack
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (105, 70)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pBasicAttack)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
