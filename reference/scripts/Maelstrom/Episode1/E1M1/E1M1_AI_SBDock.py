import App

def CreateAI(pShip, sPlacementName):

	#########################################
	# Creating PlainAI FlyWaypoints at (91, 114)
	pFlyWaypoints = App.PlainAI_Create(pShip, "FlyWaypoints")
	pFlyWaypoints.SetScriptModule("FollowWaypoints")
	pFlyWaypoints.SetInterruptable(1)
	pScript = pFlyWaypoints.GetScriptInstance()
	pScript.SetTargetWaypointName(sPlacementName)
	# Done creating PlainAI FlyWaypoints
	#########################################
	return pFlyWaypoints
