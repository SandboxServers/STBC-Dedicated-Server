import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI CircletheStarbase at (180, 77)
	pCircletheStarbase = App.PlainAI_Create(pShip, "CircletheStarbase")
	pCircletheStarbase.SetScriptModule("CircleObject")
	pCircletheStarbase.SetInterruptable(1)
	pScript = pCircletheStarbase.GetScriptInstance()
	pScript.SetFollowObjectName("Starbase 12")
	pScript.SetNearFacingVector(App.TGPoint3_GetModelLeft())
	pScript.SetRoughDistances(150, 300)
	pScript.SetCircleSpeed(8)
	# Done creating PlainAI CircletheStarbase
	#########################################

	#########################################
	# Creating PreprocessingAI AvoidObstacles at (92, 97)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pCircletheStarbase)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
