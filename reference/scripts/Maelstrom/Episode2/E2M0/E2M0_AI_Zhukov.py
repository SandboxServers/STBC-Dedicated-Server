import App

def CreateAI(pShip):
	#########################################
	# Creating PlainAI FollowSovereign at (16, 282)
	pFollowSovereign = App.PlainAI_Create(pShip, "FollowSovereign")
	pFollowSovereign.SetScriptModule("FollowObject")
	pFollowSovereign.SetInterruptable(1)
	pScript = pFollowSovereign.GetScriptInstance()
	pScript.SetFollowObjectName("Sovereign")
	pScript.SetRoughDistances(fNear = 20, fMid = 40, fFar = 80)
	# Done creating PlainAI FollowSovereign
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (16, 351)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pFollowSovereign)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
