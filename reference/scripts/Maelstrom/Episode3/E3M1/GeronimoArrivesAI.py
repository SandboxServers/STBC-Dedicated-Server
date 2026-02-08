import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI WarpToSavoy2 at (197, 107)
	pWarpToSavoy2 = App.PlainAI_Create(pShip, "WarpToSavoy2")
	pWarpToSavoy2.SetScriptModule("Warp")
	pWarpToSavoy2.SetInterruptable(1)
	pScript = pWarpToSavoy2.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.Savoy.Savoy1")
	pScript.SetDestinationPlacementName("Geronimo Start")
	pScript.SetWarpDuration(0)
	# Done creating PlainAI WarpToSavoy2
	#########################################
	#########################################
	# Creating PlainAI FollowWaypoints at (198, 147)
	pFollowWaypoints = App.PlainAI_Create(pShip, "FollowWaypoints")
	pFollowWaypoints.SetScriptModule("FollowWaypoints")
	pFollowWaypoints.SetInterruptable(1)
	pScript = pFollowWaypoints.GetScriptInstance()
	pScript.SetTargetWaypointName("Geronimo Start")
	# Done creating PlainAI FollowWaypoints
	#########################################
	#########################################
	# Creating SequenceAI Sequence at (198, 39)
	pSequence = App.SequenceAI_Create(pShip, "Sequence")
	pSequence.SetInterruptable(1)
	pSequence.SetLoopCount(1)
	pSequence.SetResetIfInterrupted(1)
	pSequence.SetDoubleCheckAllDone(0)
	pSequence.SetSkipDormant(0)
	# SeqBlock is at (214, 69)
	pSequence.AddAI(pWarpToSavoy2)
	pSequence.AddAI(pFollowWaypoints)
	# Done creating SequenceAI Sequence
	#########################################
	return pSequence
