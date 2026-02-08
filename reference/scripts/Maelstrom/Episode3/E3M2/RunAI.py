import App
def CreateAI(pShip):




	#########################################
	# Creating PlainAI RunTowardsPlayer at (200, 70)
	pRunTowardsPlayer = App.PlainAI_Create(pShip, "RunTowardsPlayer")
	pRunTowardsPlayer.SetScriptModule("Intercept")
	pRunTowardsPlayer.SetInterruptable(1)
	pScript = pRunTowardsPlayer.GetScriptInstance()
	pScript.SetTargetObjectName("player")
	pScript.SetMaximumSpeed(3)
	# Done creating PlainAI RunTowardsPlayer
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (114, 90)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pRunTowardsPlayer)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
