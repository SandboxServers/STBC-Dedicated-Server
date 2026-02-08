import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI OrbitSovereign at (73, 266)
	pOrbitSovereign = App.PlainAI_Create(pShip, "OrbitSovereign")
	pOrbitSovereign.SetScriptModule("CircleObject")
	pOrbitSovereign.SetInterruptable(1)
	pScript = pOrbitSovereign.GetScriptInstance()
	pScript.SetFollowObjectName("Sovereign")
	pScript.SetNearFacingVector(App.TGPoint3_GetModelUp())
	pScript.SetRoughDistances(50, 70)
	pScript.SetCircleSpeed(0.5)
	# Done creating PlainAI OrbitSovereign
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (70, 340)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pOrbitSovereign)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
