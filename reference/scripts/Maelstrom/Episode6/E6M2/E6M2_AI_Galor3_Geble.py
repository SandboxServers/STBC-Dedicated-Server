import App
def CreateAI(pShip, pTargetGroup, sPlacementName):


	#########################################
	# Creating PlainAI WarpBackToGeble3 at (79, 96)
	pWarpBackToGeble3 = App.PlainAI_Create(pShip, "WarpBackToGeble3")
	pWarpBackToGeble3.SetScriptModule("Warp")
	pWarpBackToGeble3.SetInterruptable(1)
	pScript = pWarpBackToGeble3.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.Geble.Geble3")
	pScript.SetDestinationPlacementName(sPlacementName)
	# Done creating PlainAI WarpBackToGeble3
	#########################################
	#########################################
	# Creating CompoundAI BasicAttack2Targets at (231, 206)
	import AI.Compound.BasicAttack
	pBasicAttack2Targets = AI.Compound.BasicAttack.CreateAI(pShip, pTargetGroup, Easy_Difficulty = 0.28, Easy_FollowToSB12 = 0, Difficulty = 1.0, FollowToSB12 = 0, Hard_Difficulty = 1.0, Hard_FollowToSB12 = 0)
	# Done creating CompoundAI BasicAttack2Targets
	#########################################
	#########################################
	# Creating SequenceAI WarpInSequence at (123, 269)
	pWarpInSequence = App.SequenceAI_Create(pShip, "WarpInSequence")
	pWarpInSequence.SetInterruptable(1)
	pWarpInSequence.SetLoopCount(1)
	pWarpInSequence.SetResetIfInterrupted(1)
	pWarpInSequence.SetDoubleCheckAllDone(0)
	pWarpInSequence.SetSkipDormant(0)
	# SeqBlock is at (162, 180)
	pWarpInSequence.AddAI(pWarpBackToGeble3)
	pWarpInSequence.AddAI(pBasicAttack2Targets)
	# Done creating SequenceAI WarpInSequence
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (32, 309)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pWarpInSequence)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
