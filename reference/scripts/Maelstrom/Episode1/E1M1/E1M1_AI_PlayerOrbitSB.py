import App

def CreateAI(pShip):
	#########################################
	# Creating PlainAI OrbitStarbase at (39, 234)
	pOrbitStarbase = App.PlainAI_Create(pShip, "OrbitStarbase")
	pOrbitStarbase.SetScriptModule("CircleObject")
	pOrbitStarbase.SetInterruptable(1)
	pScript = pOrbitStarbase.GetScriptInstance()
	pScript.SetFollowObjectName("Starbase 12")
	pScript.SetNearFacingVector(App.TGPoint3_GetModelLeft())
	pScript.SetRoughDistances(400, 425)
	pScript.SetCircleSpeed(2)
	# Done creating PlainAI OrbitStarbase
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (39, 300)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pOrbitStarbase)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
