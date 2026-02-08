import App
def CreateAI(pShip, sPlacementName):
	#########################################
	# Creating PlainAI WarpToBeol at (233, 140)
	pWarpToBeol = App.PlainAI_Create(pShip, "WarpToBeol")
	pWarpToBeol.SetScriptModule("Warp")
	pWarpToBeol.SetInterruptable(1)
	pScript = pWarpToBeol.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.Beol.Beol4")
	pScript.SetDestinationPlacementName(sPlacementName)
	pScript.SetWarpDuration(5)
	# Done creating PlainAI WarpToBeol
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (235, 212)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pWarpToBeol)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
