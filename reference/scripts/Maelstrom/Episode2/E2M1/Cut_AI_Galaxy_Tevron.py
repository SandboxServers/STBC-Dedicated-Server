import App

def CreateAI(pShip):
	#########################################
	# Creating PlainAI FlyWaypoints at (52, 148)
	pFlyWaypoints = App.PlainAI_Create(pShip, "FlyWaypoints")
	pFlyWaypoints.SetScriptModule("FollowWaypoints")
	pFlyWaypoints.SetInterruptable(1)
	pScript = pFlyWaypoints.GetScriptInstance()
	pScript.SetTargetWaypointName("GalaxyFlyby")
	# Done creating PlainAI FlyWaypoints
	#########################################
	return pFlyWaypoints
