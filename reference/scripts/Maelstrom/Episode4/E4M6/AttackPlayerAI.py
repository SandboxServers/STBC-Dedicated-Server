import App

def CreateAI(pShip):
	#########################################
	# Creating CompoundAI AttackPlayer at (221, 160)
	import AI.Compound.BasicAttack
	pAttackPlayer = AI.Compound.BasicAttack.CreateAI(pShip, "player", Difficulty = 0.05)
	# Done creating CompoundAI AttackPlayer
	#########################################
	#########################################
	# Creating PreprocessingAI AlertLevel at (219, 111)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AlertLevel(App.ShipClass.RED_ALERT)
	## The PreprocessingAI:
	pAlertLevel = App.PreprocessingAI_Create(pShip, "AlertLevel")
	pAlertLevel.SetInterruptable(1)
	pAlertLevel.SetPreprocessingMethod(pScript, "Update")
	pAlertLevel.SetContainedAI(pAttackPlayer)
	# Done creating PreprocessingAI AlertLevel
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (219, 57)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pAlertLevel)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
