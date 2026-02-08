import App
def CreateAI(pShip, pTarget):
	sTarget = pTarget.GetName()
	fInterceptDistance = 60.0
	if App.PlacementObject_Cast(pTarget):
		fInterceptDistance = 0.0
	
	#########################################
	# Creating PlainAI Intercept at (226, 140)
	pIntercept = App.PlainAI_Create(pShip, "Intercept")
	pIntercept.SetScriptModule("Intercept")
	pIntercept.SetInterruptable(1)
	pScript = pIntercept.GetScriptInstance()
	pScript.SetTargetObjectName(sTarget)
	pScript.SetInterceptDistance(fInterceptDistance)
	pScript.SetAddObjectRadius(1)
	# Done creating PlainAI Intercept
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (189, 206)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pIntercept)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
