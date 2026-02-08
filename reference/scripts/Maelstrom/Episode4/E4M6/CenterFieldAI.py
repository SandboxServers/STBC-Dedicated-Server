import App

def CreateAI(pShip):
	#########################################
	# Creating PlainAI OnPath at (19, 165)
	pOnPath = App.PlainAI_Create(pShip, "OnPath")
	pOnPath.SetScriptModule("FollowWaypoints")
	pOnPath.SetInterruptable(1)
	pScript = pOnPath.GetScriptInstance()
	pScript.SetTargetWaypointName("PathToCenter3")
	# Done creating PlainAI OnPath
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (17, 121)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pOnPath)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	#########################################
	# Creating PlainAI CenterOfField at (126, 121)
	pCenterOfField = App.PlainAI_Create(pShip, "CenterOfField")
	pCenterOfField.SetScriptModule("FollowWaypoints")
	pCenterOfField.SetInterruptable(1)
	pScript = pCenterOfField.GetScriptInstance()
	pScript.SetTargetWaypointName("Center of Asteroid Field")
	# Done creating PlainAI CenterOfField
	#########################################
	#########################################
	# Creating SequenceAI Sequence at (70, 49)
	pSequence = App.SequenceAI_Create(pShip, "Sequence")
	pSequence.SetInterruptable(1)
	pSequence.SetLoopCount(1)
	pSequence.SetResetIfInterrupted(1)
	pSequence.SetDoubleCheckAllDone(0)
	pSequence.SetSkipDormant(0)
	# SeqBlock is at (100, 80)
	pSequence.AddAI(pAvoidObstacles)
	pSequence.AddAI(pCenterOfField)
	# Done creating SequenceAI Sequence
	#########################################
	return pSequence
