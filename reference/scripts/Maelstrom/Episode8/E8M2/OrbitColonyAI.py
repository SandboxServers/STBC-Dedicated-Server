import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI OrbitColony at (185, 102)
	pOrbitColony = App.PlainAI_Create(pShip, "OrbitColony")
	pOrbitColony.SetScriptModule("CircleObject")
	pOrbitColony.SetInterruptable(1)
	pScript = pOrbitColony.GetScriptInstance()
	pScript.SetFollowObjectName("Kessok Colony")
	pScript.SetNearFacingVector(App.TGPoint3_GetModelUp())
	pScript.SetRoughDistances(150, 200)
	pScript.SetCircleSpeed(0.5)
	# Done creating PlainAI OrbitColony
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
	pAvoidObstacles.SetContainedAI(pOrbitColony)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
