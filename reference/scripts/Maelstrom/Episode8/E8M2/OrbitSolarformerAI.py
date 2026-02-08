import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI OrbitSolarformer at (185, 102)
	pOrbitSolarformer = App.PlainAI_Create(pShip, "OrbitSolarformer")
	pOrbitSolarformer.SetScriptModule("CircleObject")
	pOrbitSolarformer.SetInterruptable(1)
	pScript = pOrbitSolarformer.GetScriptInstance()
	pScript.SetFollowObjectName("Solarformer")
	pScript.SetNearFacingVector(App.TGPoint3_GetModelUp())
	pScript.SetRoughDistances(150, 200)
	pScript.SetCircleSpeed(0.25)
	# Done creating PlainAI OrbitSolarformer
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (94, 122)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pOrbitSolarformer)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
