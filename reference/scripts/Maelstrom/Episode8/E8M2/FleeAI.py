import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI Flee at (270, 72)
	pFlee = App.PlainAI_Create(pShip, "Flee")
	pFlee.SetScriptModule("Flee")
	pFlee.SetInterruptable(1)
	pScript = pFlee.GetScriptInstance()
	pScript.SetFleeFromGroup("player")
	pScript.SetSpeed(1)
	# Done creating PlainAI Flee
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (187, 92)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pFlee)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
