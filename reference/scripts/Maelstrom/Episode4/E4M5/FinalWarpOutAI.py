import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI FinalWarpOut at (216, 80)
	pFinalWarpOut = App.PlainAI_Create(pShip, "FinalWarpOut")
	pFinalWarpOut.SetScriptModule("Warp")
	pFinalWarpOut.SetInterruptable(1)
	# Done creating PlainAI FinalWarpOut
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
	pAvoidObstacles.SetContainedAI(pFinalWarpOut)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
