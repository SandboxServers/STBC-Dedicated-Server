import App

def CreateAI(pShip, sWaypoint, fDelay):



	#########################################
	# Creating PlainAI Stay at (57, 295)
	pStay = App.PlainAI_Create(pShip, "Stay")
	pStay.SetScriptModule("Stay")
	pStay.SetInterruptable(1)
	# Done creating PlainAI Stay
	#########################################
	#########################################
	# Creating ConditionalAI Wait at (58, 254)
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
	# Creating PreprocessingAI GreenAlert at (56, 202)
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
	# Creating PlainAI PlayFelixLine at (146, 202)
	pPlayFelixLine = App.PlainAI_Create(pShip, "PlayFelixLine")
	pPlayFelixLine.SetScriptModule("RunScript")
	pPlayFelixLine.SetInterruptable(1)
	pScript = pPlayFelixLine.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode7.E7M3.E7M3")
	pScript.SetFunction("DefenderPoweredUp")
	pScript.SetArguments(pShip.GetName())
	# Done creating PlainAI PlayFelixLine
	#########################################
	#########################################
	# Creating PlainAI FollowWaypoint at (233, 202)
	pFollowWaypoint = App.PlainAI_Create(pShip, "FollowWaypoint")
	pFollowWaypoint.SetScriptModule("FollowWaypoints")
	pFollowWaypoint.SetInterruptable(1)
	pScript = pFollowWaypoint.GetScriptInstance()
	pScript.SetTargetWaypointName(sWaypoint)
	# Done creating PlainAI FollowWaypoint
	#########################################
	#########################################
	# Creating CompoundAI Attack at (353, 300)
	import AI.Compound.BasicAttack
	pAttack = AI.Compound.BasicAttack.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode7.E7M3.E7M3", "pFriendlies"), Difficulty = 0.8, SmartPhasers = 1)
	# Done creating CompoundAI Attack
	#########################################
	#########################################
	# Creating PreprocessingAI RedAlert at (353, 255)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AlertLevel(App.ShipClass.RED_ALERT)
	## The PreprocessingAI:
	pRedAlert = App.PreprocessingAI_Create(pShip, "RedAlert")
	pRedAlert.SetInterruptable(1)
	pRedAlert.SetPreprocessingMethod(pScript, "Update")
	pRedAlert.SetContainedAI(pAttack)
	# Done creating PreprocessingAI RedAlert
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (351, 203)
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
	#########################################
	# Creating SequenceAI Sequence at (242, 68)
	pSequence = App.SequenceAI_Create(pShip, "Sequence")
	pSequence.SetInterruptable(1)
	pSequence.SetLoopCount(1)
	pSequence.SetResetIfInterrupted(0)
	pSequence.SetDoubleCheckAllDone(0)
	pSequence.SetSkipDormant(0)
	# SeqBlock is at (249, 99)
	pSequence.AddAI(pGreenAlert)
	pSequence.AddAI(pPlayFelixLine)
	pSequence.AddAI(pFollowWaypoint)
	pSequence.AddAI(pAvoidObstacles)
	# Done creating SequenceAI Sequence
	#########################################
	#########################################
	# Creating ConditionalAI IfPlayerInSet at (242, 24)
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
