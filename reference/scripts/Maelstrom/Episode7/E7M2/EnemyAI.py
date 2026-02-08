import App
def CreateAI(pShip, sWaypoint):


	#########################################
	# Creating PlainAI Waypoint at (338, 142)
	pWaypoint = App.PlainAI_Create(pShip, "Waypoint")
	pWaypoint.SetScriptModule("FollowWaypoints")
	pWaypoint.SetInterruptable(1)
	pScript = pWaypoint.GetScriptInstance()
	pScript.SetTargetWaypointName(sWaypoint)
	# Done creating PlainAI Waypoint
	#########################################
	#########################################
	# Creating CompoundAI AttackStation at (374, 102)
	import AI.Compound.BasicAttack
	pAttackStation = AI.Compound.BasicAttack.CreateAI(pShip, "Lyra Station", Difficulty = 1.0)
	# Done creating CompoundAI AttackStation
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (240, 102)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (329, 109)
	pPriorityList.AddAI(pWaypoint, 1)
	pPriorityList.AddAI(pAttackStation, 2)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating ConditionalAI Timer at (199, 56)
	## Conditions:
	#### Condition TimePassed
	pTimePassed = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 90, 1)
	## Evaluation function:
	def EvalFunc(bTimePassed):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bTimePassed:
			return DONE
		return ACTIVE
	## The ConditionalAI:
	pTimer = App.ConditionalAI_Create(pShip, "Timer")
	pTimer.SetInterruptable(1)
	pTimer.SetContainedAI(pPriorityList)
	pTimer.AddCondition(pTimePassed)
	pTimer.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI Timer
	#########################################
	#########################################
	# Creating CompoundAI Attack at (245, 8)
	import AI.Compound.BasicAttack
	pAttack = AI.Compound.BasicAttack.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode7.E7M2.E7M2", "pFriendlies"), Difficulty = 1.0)
	# Done creating CompoundAI Attack
	#########################################
	#########################################
	# Creating SequenceAI Sequence at (97, 8)
	pSequence = App.SequenceAI_Create(pShip, "Sequence")
	pSequence.SetInterruptable(1)
	pSequence.SetLoopCount(1)
	pSequence.SetResetIfInterrupted(1)
	pSequence.SetDoubleCheckAllDone(0)
	pSequence.SetSkipDormant(0)
	# SeqBlock is at (190, 15)
	pSequence.AddAI(pTimer)
	pSequence.AddAI(pAttack)
	# Done creating SequenceAI Sequence
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (10, 28)
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
