import App

def CreateAI(pShip, sPlacement):

	#########################################
	# Creating PlainAI WarpToCebelrai2 at (218, 178)
	pWarpToCebelrai2 = App.PlainAI_Create(pShip, "WarpToCebelrai2")
	pWarpToCebelrai2.SetScriptModule("Warp")
	pWarpToCebelrai2.SetInterruptable(1)
	pScript = pWarpToCebelrai2.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.Cebalrai.Cebalrai2")
	pScript.SetDestinationPlacementName(sPlacement)
	# Done creating PlainAI WarpToCebelrai2
	#########################################
	#########################################
	# Creating PreprocessingAI RedAlert at (216, 135)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AlertLevel(App.ShipClass.RED_ALERT)
	## The PreprocessingAI:
	pRedAlert = App.PreprocessingAI_Create(pShip, "RedAlert")
	pRedAlert.SetInterruptable(1)
	pRedAlert.SetPreprocessingMethod(pScript, "Update")
	pRedAlert.SetContainedAI(pWarpToCebelrai2)
	# Done creating PreprocessingAI RedAlert
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (215, 78)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pRedAlert)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
