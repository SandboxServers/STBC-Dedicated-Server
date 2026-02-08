import App

def CreateAI(pShip, sPlacementName):

	#########################################
	# Creating PlainAI WarpIn at (280, 143)
	pWarpIn = App.PlainAI_Create(pShip, "WarpIn")
	pWarpIn.SetScriptModule("Warp")
	pWarpIn.SetInterruptable(1)
	pScript = pWarpIn.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.Ascella.Ascella3")
	pScript.SetDestinationPlacementName(sPlacementName)
	pScript.WarpBlindly(1)
	# Done creating PlainAI WarpIn
	#########################################
	#########################################
	# Creating CompoundAI Attack at (312, 108)
	import AI.Compound.BasicAttack
	pAttack = AI.Compound.BasicAttack.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode7.E7M3.E7M3", "pFriendlies"))
	# Done creating CompoundAI Attack
	#########################################
	#########################################
	# Creating SequenceAI Sequence at (178, 108)
	pSequence = App.SequenceAI_Create(pShip, "Sequence")
	pSequence.SetInterruptable(1)
	pSequence.SetLoopCount(1)
	pSequence.SetResetIfInterrupted(1)
	pSequence.SetDoubleCheckAllDone(0)
	pSequence.SetSkipDormant(0)
	# SeqBlock is at (271, 115)
	pSequence.AddAI(pWarpIn)
	pSequence.AddAI(pAttack)
	# Done creating SequenceAI Sequence
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (92, 128)
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
