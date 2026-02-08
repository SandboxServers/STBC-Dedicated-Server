import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI FlyToShuttleWay1 at (199, 184)
	pFlyToShuttleWay1 = App.PlainAI_Create(pShip, "FlyToShuttleWay1")
	pFlyToShuttleWay1.SetScriptModule("FollowWaypoints")
	pFlyToShuttleWay1.SetInterruptable(1)
	pScript = pFlyToShuttleWay1.GetScriptInstance()
	pScript.SetTargetWaypointName("ShuttleWay1")
	# Done creating PlainAI FlyToShuttleWay1
	#########################################
	return pFlyToShuttleWay1
