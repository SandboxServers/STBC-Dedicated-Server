import App

def CreateAI(pShip, sPlacement):

	#########################################
	# Creating PlainAI WarpToNepenthe1 at (218, 178)
	pWarpToNepenthe1 = App.PlainAI_Create(pShip, "WarpToNepenthe1")
	pWarpToNepenthe1.SetScriptModule("Warp")
	pWarpToNepenthe1.SetInterruptable(1)
	pScript = pWarpToNepenthe1.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.Nepenthe.Nepenthe1")
	pScript.SetDestinationPlacementName(sPlacement)
	# Done creating PlainAI WarpToNepenthe1
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
	pRedAlert.SetContainedAI(pWarpToNepenthe1)
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
