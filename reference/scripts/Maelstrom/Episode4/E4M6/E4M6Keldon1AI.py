import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI FollowWaypoint at (208, 129)
	pFollowWaypoint = App.PlainAI_Create(pShip, "FollowWaypoint")
	pFollowWaypoint.SetScriptModule("FollowWaypoints")
	pFollowWaypoint.SetInterruptable(1)
	pScript = pFollowWaypoint.GetScriptInstance()
	pScript.SetTargetWaypointName("Keldon1 Warp")
	# Done creating PlainAI FollowWaypoint
	#########################################

	#########################################
	# Creating PreprocessingAI AvoidObstacles at (92, 136)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pFollowWaypoint)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
