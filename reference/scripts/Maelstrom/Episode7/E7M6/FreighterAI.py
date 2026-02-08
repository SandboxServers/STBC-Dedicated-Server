import App

def CreateAI(pShip, pcWaypoint):





	#########################################
	# Creating PlainAI GoToWarpWaypoint at (295, 85)
	pGoToWarpWaypoint = App.PlainAI_Create(pShip, "GoToWarpWaypoint")
	pGoToWarpWaypoint.SetScriptModule("FollowWaypoints")
	pGoToWarpWaypoint.SetInterruptable(1)
	pScript = pGoToWarpWaypoint.GetScriptInstance()
	pScript.SetTargetWaypointName(pcWaypoint)
	# Done creating PlainAI GoToWarpWaypoint
	#########################################
	#########################################
	# Creating PlainAI Warp at (344, 34)
	pWarp = App.PlainAI_Create(pShip, "Warp")
	pWarp.SetScriptModule("Warp")
	pWarp.SetInterruptable(1)
	# Done creating PlainAI Warp
	#########################################
	#########################################
	# Creating SequenceAI Sequence at (187, 34)
	pSequence = App.SequenceAI_Create(pShip, "Sequence")
	pSequence.SetInterruptable(1)
	pSequence.SetLoopCount(1)
	pSequence.SetResetIfInterrupted(1)
	pSequence.SetDoubleCheckAllDone(0)
	pSequence.SetSkipDormant(0)
	# SeqBlock is at (286, 41)
	pSequence.AddAI(pGoToWarpWaypoint)
	pSequence.AddAI(pWarp)
	# Done creating SequenceAI Sequence
	#########################################
	#########################################
	# Creating ConditionalAI IfPlayerInSet at (100, 54)
	## Conditions:
	#### Condition PlayerInSet
	pPlayerInSet = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", "player", "Alioth6")
	## Evaluation function:
	def EvalFunc(bPlayerInSet):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bPlayerInSet:
			return ACTIVE
		else:
			return DORMANT
	## The ConditionalAI:
	pIfPlayerInSet = App.ConditionalAI_Create(pShip, "IfPlayerInSet")
	pIfPlayerInSet.SetInterruptable(1)
	pIfPlayerInSet.SetContainedAI(pSequence)
	pIfPlayerInSet.AddCondition(pPlayerInSet)
	pIfPlayerInSet.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI IfPlayerInSet
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (13, 74)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pIfPlayerInSet)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
