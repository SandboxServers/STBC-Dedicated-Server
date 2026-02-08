import App

def CreateAI(pShip, *lTargets):
	pAllTargetsGroup = App.ObjectGroup_ForceToGroup(lTargets)
	sInitialTarget = pAllTargetsGroup.GetNameTuple()[0]


	#########################################
	# Creating PlainAI MoveIn at (243, 176)
	pMoveIn = App.PlainAI_Create(pShip, "MoveIn")
	pMoveIn.SetScriptModule("FollowObject")
	pMoveIn.SetInterruptable(1)
	pScript = pMoveIn.GetScriptInstance()
	pScript.SetFollowObjectName(sInitialTarget)
	pScript.SetRoughDistances(40.0, 60.0, 100.0)
	# Done creating PlainAI MoveIn
	#########################################
	#########################################
	# Creating ConditionalAI NotInRange at (202, 140)
	## Conditions:
	#### Condition InRange
	pInRange = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 60.0, sInitialTarget, pShip.GetName())
	## Evaluation function:
	def EvalFunc(bInRange):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bInRange:
			return DONE
		return ACTIVE
	## The ConditionalAI:
	pNotInRange = App.ConditionalAI_Create(pShip, "NotInRange")
	pNotInRange.SetInterruptable(1)
	pNotInRange.SetContainedAI(pMoveIn)
	pNotInRange.AddCondition(pInRange)
	pNotInRange.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI NotInRange
	#########################################
	#########################################
	# Creating PlainAI TurnBack at (218, 94)
	pTurnBack = App.PlainAI_Create(pShip, "TurnBack")
	pTurnBack.SetScriptModule("TurnToOrientation")
	pTurnBack.SetInterruptable(1)
	pScript = pTurnBack.GetScriptInstance()
	pScript.SetObjectName(sInitialTarget)
	pScript.SetPrimaryDirection(App.TGPoint3_GetModelBackward())
	pScript.SetDoneOnLineup(1)
	# Done creating PlainAI TurnBack
	#########################################
	#########################################
	# Creating PlainAI FlyAway at (461, 124)
	pFlyAway = App.PlainAI_Create(pShip, "FlyAway")
	pFlyAway.SetScriptModule("Flee")
	pFlyAway.SetInterruptable(1)
	pScript = pFlyAway.GetScriptInstance()
	pScript.SetFleeFromGroup(sInitialTarget)
	pScript.SetSpeed(0.5)
	# Done creating PlainAI FlyAway
	#########################################
	#########################################
	# Creating ConditionalAI WaitForWarp at (420, 86)
	## Conditions:
	#### Condition TimeElapsed
	pTimeElapsed = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 15, 1)
	## Evaluation function:
	def EvalFunc(bTimeElapsed):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bTimeElapsed:
			return DONE
		return ACTIVE
	## The ConditionalAI:
	pWaitForWarp = App.ConditionalAI_Create(pShip, "WaitForWarp")
	pWaitForWarp.SetInterruptable(1)
	pWaitForWarp.SetContainedAI(pFlyAway)
	pWaitForWarp.AddCondition(pTimeElapsed)
	pWaitForWarp.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI WaitForWarp
	#########################################
	#########################################
	# Creating PlainAI TowThroughWarp at (457, 38)
	pTowThroughWarp = App.PlainAI_Create(pShip, "TowThroughWarp")
	pTowThroughWarp.SetScriptModule("Warp")
	pTowThroughWarp.SetInterruptable(1)
	pScript = pTowThroughWarp.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.Starbase12.Starbase12")
	pScript.WarpBlindly(1)
	# Done creating PlainAI TowThroughWarp
	#########################################
	pScript.EnableTowingThroughWarp(1)
	#########################################
	# Creating SequenceAI Sequence_2 at (317, 38)
	pSequence_2 = App.SequenceAI_Create(pShip, "Sequence_2")
	pSequence_2.SetInterruptable(1)
	pSequence_2.SetLoopCount(1)
	pSequence_2.SetResetIfInterrupted(1)
	pSequence_2.SetDoubleCheckAllDone(0)
	pSequence_2.SetSkipDormant(0)
	# SeqBlock is at (411, 45)
	pSequence_2.AddAI(pWaitForWarp)
	pSequence_2.AddAI(pTowThroughWarp)
	# Done creating SequenceAI Sequence_2
	#########################################
	#########################################
	# Creating PreprocessingAI TractorDocking at (234, 58)
	## Setup:
	import AI.Preprocessors
	pTractorScript = AI.Preprocessors.FireScript(sInitialTarget)
	pTractorScript.AddTractorBeam(pShip, App.TractorBeamSystem.TBS_TOW)
	## The PreprocessingAI:
	pTractorDocking = App.PreprocessingAI_Create(pShip, "TractorDocking")
	pTractorDocking.SetInterruptable(1)
	pTractorDocking.SetPreprocessingMethod(pTractorScript, "Update")
	pTractorDocking.SetContainedAI(pSequence_2)
	# Done creating PreprocessingAI TractorDocking
	#########################################
	#########################################
	# Creating SequenceAI Sequence at (96, 13)
	pSequence = App.SequenceAI_Create(pShip, "Sequence")
	pSequence.SetInterruptable(1)
	pSequence.SetLoopCount(1)
	pSequence.SetResetIfInterrupted(1)
	pSequence.SetDoubleCheckAllDone(0)
	pSequence.SetSkipDormant(0)
	# SeqBlock is at (193, 20)
	pSequence.AddAI(pNotInRange)
	pSequence.AddAI(pTurnBack)
	pSequence.AddAI(pTractorDocking)
	# Done creating SequenceAI Sequence
	#########################################
	#########################################
	# Creating PreprocessingAI SelectTarget at (13, 33)
	## Setup:
	import AI.Preprocessors
	pSelectionPreprocess = AI.Preprocessors.SelectTarget(pAllTargetsGroup)
	## The PreprocessingAI:
	pSelectTarget = App.PreprocessingAI_Create(pShip, "SelectTarget")
	pSelectTarget.SetInterruptable(1)
	pSelectTarget.SetPreprocessingMethod(pSelectionPreprocess, "Update")
	pSelectTarget.SetContainedAI(pSequence)
	# Done creating PreprocessingAI SelectTarget
	#########################################
	return pSelectTarget
