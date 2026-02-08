import App

def CreateAI(pShip, sWaypoint, fDelay):


	#########################################
	# Creating PlainAI Stay at (54, 305)
	pStay = App.PlainAI_Create(pShip, "Stay")
	pStay.SetScriptModule("Stay")
	pStay.SetInterruptable(1)
	# Done creating PlainAI Stay
	#########################################
	#########################################
	# Creating ConditionalAI Wait at (56, 260)
	## Conditions:
	#### Condition Delay
	pDelay = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", fDelay)
	## Evaluation function:
	def EvalFunc(bDelay):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bDelay:
			return DONE
		else:
			return ACTIVE
	## The ConditionalAI:
	pWait = App.ConditionalAI_Create(pShip, "Wait")
	pWait.SetInterruptable(1)
	pWait.SetContainedAI(pStay)
	pWait.AddCondition(pDelay)
	pWait.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI Wait
	#########################################
	#########################################
	# Creating PreprocessingAI GreenAlert at (57, 207)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AlertLevel(App.ShipClass.GREEN_ALERT)
	## The PreprocessingAI:
	pGreenAlert = App.PreprocessingAI_Create(pShip, "GreenAlert")
	pGreenAlert.SetInterruptable(1)
	pGreenAlert.SetPreprocessingMethod(pScript, "Update")
	pGreenAlert.SetContainedAI(pWait)
	# Done creating PreprocessingAI GreenAlert
	#########################################
	#########################################
	# Creating PlainAI PlayFelixLine at (153, 207)
	pPlayFelixLine = App.PlainAI_Create(pShip, "PlayFelixLine")
	pPlayFelixLine.SetScriptModule("RunScript")
	pPlayFelixLine.SetInterruptable(1)
	pScript = pPlayFelixLine.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode7.E7M3.E7M3")
	pScript.SetFunction("FreighterPoweredUp")
	pScript.SetArguments(pShip.GetName())
	# Done creating PlainAI PlayFelixLine
	#########################################
	#########################################
	# Creating PlainAI FollowWaypoint at (247, 257)
	pFollowWaypoint = App.PlainAI_Create(pShip, "FollowWaypoint")
	pFollowWaypoint.SetScriptModule("FollowWaypoints")
	pFollowWaypoint.SetInterruptable(1)
	pScript = pFollowWaypoint.GetScriptInstance()
	pScript.SetTargetWaypointName(sWaypoint)
	# Done creating PlainAI FollowWaypoint
	#########################################
	#########################################
	# Creating PreprocessingAI RedAlert at (248, 207)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AlertLevel(App.ShipClass.RED_ALERT)
	## The PreprocessingAI:
	pRedAlert = App.PreprocessingAI_Create(pShip, "RedAlert")
	pRedAlert.SetInterruptable(1)
	pRedAlert.SetPreprocessingMethod(pScript, "Update")
	pRedAlert.SetContainedAI(pFollowWaypoint)
	# Done creating PreprocessingAI RedAlert
	#########################################
	#########################################
	# Creating PlainAI Warp at (344, 254)
	pWarp = App.PlainAI_Create(pShip, "Warp")
	pWarp.SetScriptModule("Warp")
	pWarp.SetInterruptable(1)
	# Done creating PlainAI Warp
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (344, 206)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pWarp)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	#########################################
	# Creating SequenceAI Sequence at (224, 69)
	pSequence = App.SequenceAI_Create(pShip, "Sequence")
	pSequence.SetInterruptable(1)
	pSequence.SetLoopCount(1)
	pSequence.SetResetIfInterrupted(1)
	pSequence.SetDoubleCheckAllDone(0)
	pSequence.SetSkipDormant(0)
	# SeqBlock is at (232, 98)
	pSequence.AddAI(pGreenAlert)
	pSequence.AddAI(pPlayFelixLine)
	pSequence.AddAI(pRedAlert)
	pSequence.AddAI(pAvoidObstacles)
	# Done creating SequenceAI Sequence
	#########################################
	#########################################
	# Creating ConditionalAI IfPlayerInSet at (224, 13)
	## Conditions:
	#### Condition PlayerInSet
	pPlayerInSet = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", "player", "Ascella3")
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
	return pIfPlayerInSet
