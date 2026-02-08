import App
def CreateAI(pShip, sTargetName):
	#########################################
	# Creating PlainAI InterceptTarget at (210, 64)
	pInterceptTarget = App.PlainAI_Create(pShip, "InterceptTarget")
	pInterceptTarget.SetScriptModule("Intercept")
	pInterceptTarget.SetInterruptable(1)
	pScript = pInterceptTarget.GetScriptInstance()
	pScript.SetTargetObjectName(sTargetName)
	pScript.SetMaximumSpeed(10.0)
	pScript.SetInterceptDistance(0)
	# Done creating PlainAI InterceptTarget
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (120, 84)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pInterceptTarget)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
