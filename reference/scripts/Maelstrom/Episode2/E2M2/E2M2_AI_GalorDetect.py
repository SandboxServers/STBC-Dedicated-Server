import App
def CreateAI(pShip):

	#########################################
	# Creating CompoundAI BasicAttackMarauder at (48, 163)
	import AI.Compound.BasicAttack
	pBasicAttackMarauder = AI.Compound.BasicAttack.CreateAI(pShip, "Marauder", Difficulty = 0.9)
	# Done creating CompoundAI BasicAttackMarauder
	#########################################
	#########################################
	# Creating PlainAI WarpOut at (156, 161)
	pWarpOut = App.PlainAI_Create(pShip, "WarpOut")
	pWarpOut.SetScriptModule("Warp")
	pWarpOut.SetInterruptable(1)
	# Done creating PlainAI WarpOut
	#########################################
	#########################################
	# Creating SequenceAI Sequence at (23, 260)
	pSequence = App.SequenceAI_Create(pShip, "Sequence")
	pSequence.SetInterruptable(1)
	pSequence.SetLoopCount(1)
	pSequence.SetResetIfInterrupted(1)
	pSequence.SetDoubleCheckAllDone(0)
	pSequence.SetSkipDormant(0)
	# SeqBlock is at (145, 241)
	pSequence.AddAI(pBasicAttackMarauder)
	pSequence.AddAI(pWarpOut)
	# Done creating SequenceAI Sequence
	#########################################
	#########################################
	# Creating PreprocessingAI RedAlert at (19, 309)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AlertLevel(App.ShipClass.RED_ALERT)
	## The PreprocessingAI:
	pRedAlert = App.PreprocessingAI_Create(pShip, "RedAlert")
	pRedAlert.SetInterruptable(1)
	pRedAlert.SetPreprocessingMethod(pScript, "Update")
	pRedAlert.SetContainedAI(pSequence)
	# Done creating PreprocessingAI RedAlert
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (18, 360)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pRedAlert)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
