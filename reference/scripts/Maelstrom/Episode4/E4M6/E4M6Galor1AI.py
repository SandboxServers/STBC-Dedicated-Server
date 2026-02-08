import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI FollowWaypoint at (269, 149)
	pFollowWaypoint = App.PlainAI_Create(pShip, "FollowWaypoint")
	pFollowWaypoint.SetScriptModule("FollowWaypoints")
	pFollowWaypoint.SetInterruptable(1)
	pScript = pFollowWaypoint.GetScriptInstance()
	pScript.SetTargetWaypointName("Galor1 Warp")
	# Done creating PlainAI FollowWaypoint
	#########################################

	#########################################
	# Creating PreprocessingAI AvoidObstacles at (117, 163)
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
