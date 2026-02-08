import App
def CreateAI(pShip, pTargetGroup):

	#########################################
	# Creating PlainAI WarpToSerris1 at (115, 157)
	pWarpToSerris1 = App.PlainAI_Create(pShip, "WarpToSerris1")
	pWarpToSerris1.SetScriptModule("Warp")
	pWarpToSerris1.SetInterruptable(1)
	pScript = pWarpToSerris1.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.Serris.Serris1")
	pScript.SetDestinationPlacementName("Galor1Enter")
	pScript.SetWarpDuration(10)
	# Done creating PlainAI WarpToSerris1
	#########################################
	#########################################
	# Creating CompoundAI BasicAttackTargets at (263, 154)
	import AI.Compound.BasicAttack
	pBasicAttackTargets = AI.Compound.BasicAttack.CreateAI(pShip, pTargetGroup, Easy_Difficulty = 0.44, Easy_FollowToSB12 = 0, Difficulty = 1.0, FollowToSB12 = 0, Hard_Difficulty = 1.0, Hard_FollowToSB12 = 0)
	# Done creating CompoundAI BasicAttackTargets
	#########################################
	#########################################
	# Creating SequenceAI Sequence at (132, 286)
	pSequence = App.SequenceAI_Create(pShip, "Sequence")
	pSequence.SetInterruptable(1)
	pSequence.SetLoopCount(1)
	pSequence.SetResetIfInterrupted(1)
	pSequence.SetDoubleCheckAllDone(0)
	pSequence.SetSkipDormant(0)
	# SeqBlock is at (198, 223)
	pSequence.AddAI(pWarpToSerris1)
	pSequence.AddAI(pBasicAttackTargets)
	# Done creating SequenceAI Sequence
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (48, 360)
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
