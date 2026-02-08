import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI StareAtPlayer at (152, 59)
	pStareAtPlayer = App.PlainAI_Create(pShip, "StareAtPlayer")
	pStareAtPlayer.SetScriptModule("StationaryAttack")
	pStareAtPlayer.SetInterruptable(1)
	pScript = pStareAtPlayer.GetScriptInstance()
	pScript.SetTargetObjectName("player")
	# Done creating PlainAI StareAtPlayer
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (50, 50)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pStareAtPlayer)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
