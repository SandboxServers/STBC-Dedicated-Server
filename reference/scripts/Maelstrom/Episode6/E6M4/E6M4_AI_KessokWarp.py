import App

def CreateAI(pShip):
	#########################################
	# Creating PlainAI WarpToDeepSpace at (259, 80)
	pWarpToDeepSpace = App.PlainAI_Create(pShip, "WarpToDeepSpace")
	pWarpToDeepSpace.SetScriptModule("Warp")
	pWarpToDeepSpace.SetInterruptable(1)
	# Done creating PlainAI WarpToDeepSpace
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (196, 261)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pWarpToDeepSpace)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
