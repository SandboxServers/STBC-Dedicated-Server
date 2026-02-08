import App

def CreateAI(pShip):
	#########################################
	# Creating PlainAI CircleGeronimo at (151, 30)
	pCircleGeronimo = App.PlainAI_Create(pShip, "CircleGeronimo")
	pCircleGeronimo.SetScriptModule("CircleObject")
	pCircleGeronimo.SetInterruptable(1)
	pScript = pCircleGeronimo.GetScriptInstance()
	pScript.SetFollowObjectName("USS Geronimo")
	pScript.SetNearFacingVector(App.TGPoint3_GetModelUp())
	pScript.SetRoughDistances(300, 500)
	pScript.SetCircleSpeed(1)
	# Done creating PlainAI CircleGeronimo
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
	pAvoidObstacles.SetContainedAI(pCircleGeronimo)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
