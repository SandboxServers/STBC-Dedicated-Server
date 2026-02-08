import App

def CreateAI(pShip, sPlacementName):

	#########################################
	# Creating PlainAI WarpToDeepSpace at (51, 186)
	pWarpToDeepSpace = App.PlainAI_Create(pShip, "WarpToDeepSpace")
	pWarpToDeepSpace.SetScriptModule("Warp")
	pWarpToDeepSpace.SetInterruptable(1)
	pScript = pWarpToDeepSpace.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.DeepSpace.DeepSpace")
	pScript.SetDestinationPlacementName(sPlacementName)
	# Done creating PlainAI WarpToDeepSpace
	#########################################
	#########################################
	# Creating PreprocessingAI GreenAlert at (51, 254)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AlertLevel(App.ShipClass.GREEN_ALERT)
	## The PreprocessingAI:
	pGreenAlert = App.PreprocessingAI_Create(pShip, "GreenAlert")
	pGreenAlert.SetInterruptable(1)
	pGreenAlert.SetPreprocessingMethod(pScript, "Update")
	pGreenAlert.SetContainedAI(pWarpToDeepSpace)
	# Done creating PreprocessingAI GreenAlert
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (51, 303)
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
