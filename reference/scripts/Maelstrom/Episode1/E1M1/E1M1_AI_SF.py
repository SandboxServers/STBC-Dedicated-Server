import App

def CreateAI(pShip):
	#########################################
	# Creating PlainAI OrbitStarbase at (37, 168)
	pOrbitStarbase = App.PlainAI_Create(pShip, "OrbitStarbase")
	pOrbitStarbase.SetScriptModule("CircleObject")
	pOrbitStarbase.SetInterruptable(1)
	pScript = pOrbitStarbase.GetScriptInstance()
	pScript.SetFollowObjectName("Starbase 12")
	pScript.SetNearFacingVector(App.TGPoint3_GetModelLeft())
	pScript.SetRoughDistances(350, 425)
	pScript.SetCircleSpeed(0.5)
	# Done creating PlainAI OrbitStarbase
	#########################################
	#########################################
	# Creating PreprocessingAI GreenAlert at (38, 240)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AlertLevel(App.ShipClass.GREEN_ALERT)
	## The PreprocessingAI:
	pGreenAlert = App.PreprocessingAI_Create(pShip, "GreenAlert")
	pGreenAlert.SetInterruptable(1)
	pGreenAlert.SetPreprocessingMethod(pScript, "Update")
	pGreenAlert.SetContainedAI(pOrbitStarbase)
	# Done creating PreprocessingAI GreenAlert
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
	pAvoidObstacles.SetContainedAI(pGreenAlert)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
