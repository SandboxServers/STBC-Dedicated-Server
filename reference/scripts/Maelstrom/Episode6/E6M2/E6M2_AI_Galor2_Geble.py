import App
def CreateAI(pShip, pTargetGroup, sPlacementName):


	#########################################
	# Creating PlainAI WarpBackToGeble3 at (109, 142)
	pWarpBackToGeble3 = App.PlainAI_Create(pShip, "WarpBackToGeble3")
	pWarpBackToGeble3.SetScriptModule("Warp")
	pWarpBackToGeble3.SetInterruptable(1)
	pScript = pWarpBackToGeble3.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.Geble.Geble3")
	pScript.SetDestinationPlacementName(sPlacementName)
	# Done creating PlainAI WarpBackToGeble3
	#########################################
	#########################################
	# Creating PlainAI Call_GalorWarpsOut at (268, 41)
	pCall_GalorWarpsOut = App.PlainAI_Create(pShip, "Call_GalorWarpsOut")
	pCall_GalorWarpsOut.SetScriptModule("RunScript")
	pCall_GalorWarpsOut.SetInterruptable(1)
	pScript = pCall_GalorWarpsOut.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode6.E6M2.E6M2")
	pScript.SetFunction("SecondGalorWarpOut")
	# Done creating PlainAI Call_GalorWarpsOut
	#########################################
	#########################################
	# Creating PlainAI WarpToDeepSpace at (408, 40)
	pWarpToDeepSpace = App.PlainAI_Create(pShip, "WarpToDeepSpace")
	pWarpToDeepSpace.SetScriptModule("Warp")
	pWarpToDeepSpace.SetInterruptable(1)
	pScript = pWarpToDeepSpace.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.DeepSpace.DeepSpace")
	# Done creating PlainAI WarpToDeepSpace
	#########################################
	#########################################
	# Creating SequenceAI WarpOutSequence at (294, 165)
	pWarpOutSequence = App.SequenceAI_Create(pShip, "WarpOutSequence")
	pWarpOutSequence.SetInterruptable(1)
	pWarpOutSequence.SetLoopCount(1)
	pWarpOutSequence.SetResetIfInterrupted(1)
	pWarpOutSequence.SetDoubleCheckAllDone(0)
	pWarpOutSequence.SetSkipDormant(0)
	# SeqBlock is at (336, 115)
	pWarpOutSequence.AddAI(pCall_GalorWarpsOut)
	pWarpOutSequence.AddAI(pWarpToDeepSpace)
	# Done creating SequenceAI WarpOutSequence
	#########################################
	#########################################
	# Creating ConditionalAI TakingHullDamage at (224, 214)
	## Conditions:
	#### Condition HullTakingDamage
	pHullTakingDamage = App.ConditionScript_Create("Conditions.ConditionAttackedBy", "ConditionAttackedBy", pShip.GetName(),  "player", 2, 0.3, 99)
	## Evaluation function:
	def EvalFunc(bHullTakingDamage):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bHullTakingDamage):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pTakingHullDamage = App.ConditionalAI_Create(pShip, "TakingHullDamage")
	pTakingHullDamage.SetInterruptable(1)
	pTakingHullDamage.SetContainedAI(pWarpOutSequence)
	pTakingHullDamage.AddCondition(pHullTakingDamage)
	pTakingHullDamage.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI TakingHullDamage
	#########################################
	#########################################
	# Creating CompoundAI BasicAttack2Targets at (390, 244)
	import AI.Compound.BasicAttack
	pBasicAttack2Targets = AI.Compound.BasicAttack.CreateAI(pShip, pTargetGroup, Difficulty = 1.0)
	# Done creating CompoundAI BasicAttack2Targets
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (180, 292)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (310, 317)
	pPriorityList.AddAI(pTakingHullDamage, 1)
	pPriorityList.AddAI(pBasicAttack2Targets, 2)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating SequenceAI WarpInSequence at (55, 259)
	pWarpInSequence = App.SequenceAI_Create(pShip, "WarpInSequence")
	pWarpInSequence.SetInterruptable(1)
	pWarpInSequence.SetLoopCount(1)
	pWarpInSequence.SetResetIfInterrupted(1)
	pWarpInSequence.SetDoubleCheckAllDone(0)
	pWarpInSequence.SetSkipDormant(0)
	# SeqBlock is at (129, 211)
	pWarpInSequence.AddAI(pWarpBackToGeble3)
	pWarpInSequence.AddAI(pPriorityList)
	# Done creating SequenceAI WarpInSequence
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (29, 335)
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
