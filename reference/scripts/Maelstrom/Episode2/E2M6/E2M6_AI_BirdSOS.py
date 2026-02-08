import App

def CreateAI(pShip, sPlacementName, pTargetGroup):

	#########################################
	# Creating PlainAI WarpToBiranu2 at (135, 98)
	pWarpToBiranu2 = App.PlainAI_Create(pShip, "WarpToBiranu2")
	pWarpToBiranu2.SetScriptModule("Warp")
	pWarpToBiranu2.SetInterruptable(1)
	pScript = pWarpToBiranu2.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.Biranu.Biranu2")
	pScript.SetDestinationPlacementName(sPlacementName)
	# Done creating PlainAI WarpToBiranu2
	#########################################
	#########################################
	# Creating CompoundAI BasicAttack at (269, 100)
	import AI.Compound.BasicAttack
	pBasicAttack = AI.Compound.BasicAttack.CreateAI(pShip, pTargetGroup, Difficulty = 0.5, MaxFiringRange = 405.0, AvoidTorps = 1, AggressivePulseWeapons = 0, ChooseSubsystemTargets = 1, SmartShields = 1, SmartTorpSelection = 0, UseCloaking = 1, Hard_Difficulty = 0.7, Hard_MaxFiringRange = 304.0, Hard_SmartShields = 0, Hard_SmartTorpSelection = 0, Hard_UseCloaking = 1)
	# Done creating CompoundAI BasicAttack
	#########################################
	#########################################
	# Creating PlainAI IntercetBiranuStation at (367, 103)
	pIntercetBiranuStation = App.PlainAI_Create(pShip, "IntercetBiranuStation")
	pIntercetBiranuStation.SetScriptModule("Intercept")
	pIntercetBiranuStation.SetInterruptable(1)
	pScript = pIntercetBiranuStation.GetScriptInstance()
	pScript.SetTargetObjectName("Biranu Station")
	pScript.SetInterceptDistance(150)
	pScript.SetAddObjectRadius(bUseRadius = 0)
	# Done creating PlainAI IntercetBiranuStation
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (210, 162)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (330, 164)
	pPriorityList.AddAI(pBasicAttack, 1)
	pPriorityList.AddAI(pIntercetBiranuStation, 2)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating SequenceAI Sequence at (22, 189)
	pSequence = App.SequenceAI_Create(pShip, "Sequence")
	pSequence.SetInterruptable(1)
	pSequence.SetLoopCount(1)
	pSequence.SetResetIfInterrupted(1)
	pSequence.SetDoubleCheckAllDone(0)
	pSequence.SetSkipDormant(1)
	# SeqBlock is at (160, 195)
	pSequence.AddAI(pWarpToBiranu2)
	pSequence.AddAI(pPriorityList)
	# Done creating SequenceAI Sequence
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (21, 249)
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
