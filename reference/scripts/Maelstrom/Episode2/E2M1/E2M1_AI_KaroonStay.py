import App

def CreateAI(pShip):
	#########################################
	# Creating PlainAI FlyToExit at (78, 144)
	pFlyToExit = App.PlainAI_Create(pShip, "FlyToExit")
	pFlyToExit.SetScriptModule("FollowWaypoints")
	pFlyToExit.SetInterruptable(1)
	pScript = pFlyToExit.GetScriptInstance()
	pScript.SetTargetWaypointName("KaroonExit")
	# Done creating PlainAI FlyToExit
	#########################################
	#########################################
	# Creating PlainAI StayPut at (186, 149)
	pStayPut = App.PlainAI_Create(pShip, "StayPut")
	pStayPut.SetScriptModule("Stay")
	pStayPut.SetInterruptable(1)
	# Done creating PlainAI StayPut
	#########################################
	#########################################
	# Creating SequenceAI Sequence at (38, 198)
	pSequence = App.SequenceAI_Create(pShip, "Sequence")
	pSequence.SetInterruptable(1)
	pSequence.SetLoopCount(1)
	pSequence.SetResetIfInterrupted(1)
	pSequence.SetDoubleCheckAllDone(0)
	pSequence.SetSkipDormant(0)
	# SeqBlock is at (162, 201)
	pSequence.AddAI(pFlyToExit)
	pSequence.AddAI(pStayPut)
	# Done creating SequenceAI Sequence
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (36, 246)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pSequence)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
