import App

def CreateAI(pShip, pSideOfShip):

	#########################################
	# Creating PlainAI Follow at (268, 150)
	pFollow = App.PlainAI_Create(pShip, "Follow")
	pFollow.SetScriptModule("MoveToObjectSide")
	pFollow.SetInterruptable(1)
	pScript = pFollow.GetScriptInstance()
	pScript.SetObjectSide(pSideOfShip)
	pScript.SetObjectName("G5")
	pScript.SetMaxDistance(100)
	# Done creating PlainAI Follow
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (121, 137)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pFollow)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
