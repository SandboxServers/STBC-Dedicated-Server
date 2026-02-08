import App

def CreateAI(pShip):
	#########################################
	# Creating PlainAI WarpOut at (208, 161)
	pWarpOut = App.PlainAI_Create(pShip, "WarpOut")
	pWarpOut.SetScriptModule("Warp")
	pWarpOut.SetInterruptable(1)
	# Done creating PlainAI WarpOut
	#########################################
	#########################################
	# Creating PreprocessingAI Cloak at (205, 115)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.CloakShip(1)
	## The PreprocessingAI:
	pCloak = App.PreprocessingAI_Create(pShip, "Cloak")
	pCloak.SetInterruptable(1)
	pCloak.SetPreprocessingMethod(pScript, "Update")
	pCloak.SetContainedAI(pWarpOut)
	# Done creating PreprocessingAI Cloak
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (206, 66)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pCloak)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
