import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI WarpOut at (157, 282)
	pWarpOut = App.PlainAI_Create(pShip, "WarpOut")
	pWarpOut.SetScriptModule("Warp")
	pWarpOut.SetInterruptable(1)
	# Done creating PlainAI WarpOut
	#########################################
	#########################################
	# Creating ConditionalAI StationDead at (116, 233)
	## Conditions:
	#### Condition StationInSet
	pStationInSet = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", "Litvok Nor", "Alioth6")
	## Evaluation function:
	def EvalFunc(bStationInSet):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if(bStationInSet):
			return DORMANT
		return ACTIVE
	## The ConditionalAI:
	pStationDead = App.ConditionalAI_Create(pShip, "StationDead")
	pStationDead.SetInterruptable(1)
	pStationDead.SetContainedAI(pWarpOut)
	pStationDead.AddCondition(pStationInSet)
	pStationDead.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI StationDead
	#########################################
	#########################################
	# Creating CompoundAI FollowPlayer at (257, 290)
	import AI.Compound.FollowThroughWarp
	pFollowPlayer = AI.Compound.FollowThroughWarp.CreateAI(pShip, "player")
	# Done creating CompoundAI FollowPlayer
	#########################################
	#########################################
	# Creating ConditionalAI PlayerNotInSB12 at (216, 246)
	## Conditions:
	#### Condition PlayerInSB12Set
	pPlayerInSB12Set = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", "player", "Starbase12")
	#### Condition PlayerInWarp
	pPlayerInWarp = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", "player", "warp")
	## Evaluation function:
	def EvalFunc(bPlayerInSB12Set, bPlayerInWarp):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if(bPlayerInSB12Set or bPlayerInWarp):
			return DORMANT
		return ACTIVE
	## The ConditionalAI:
	pPlayerNotInSB12 = App.ConditionalAI_Create(pShip, "PlayerNotInSB12")
	pPlayerNotInSB12.SetInterruptable(1)
	pPlayerNotInSB12.SetContainedAI(pFollowPlayer)
	pPlayerNotInSB12.AddCondition(pPlayerInSB12Set)
	pPlayerNotInSB12.AddCondition(pPlayerInWarp)
	pPlayerNotInSB12.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI PlayerNotInSB12
	#########################################
	#########################################
	# Creating PlainAI InterceptPlayer at (387, 304)
	pInterceptPlayer = App.PlainAI_Create(pShip, "InterceptPlayer")
	pInterceptPlayer.SetScriptModule("Intercept")
	pInterceptPlayer.SetInterruptable(1)
	pScript = pInterceptPlayer.GetScriptInstance()
	pScript.SetTargetObjectName("player")
	# Done creating PlainAI InterceptPlayer
	#########################################
	#########################################
	# Creating ConditionalAI Delay at (346, 256)
	## Conditions:
	#### Condition TimerElapsed
	pTimerElapsed = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 30)
	## Evaluation function:
	def EvalFunc(bTimerElapsed):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if(bTimerElapsed):
			return DONE
		return ACTIVE
	## The ConditionalAI:
	pDelay = App.ConditionalAI_Create(pShip, "Delay")
	pDelay.SetInterruptable(1)
	pDelay.SetContainedAI(pInterceptPlayer)
	pDelay.AddCondition(pTimerElapsed)
	pDelay.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI Delay
	#########################################
	#########################################
	# Creating CompoundAI Attack at (394, 197)
	import Ai.Compound.BasicAttack
	pAttack = Ai.Compound.BasicAttack.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode7.E7M6.E7M6", "pFriendlies"), Difficulty = 0.85)
	# Done creating CompoundAI Attack
	#########################################
	#########################################
	# Creating SequenceAI WaitThenAttack at (234, 197)
	pWaitThenAttack = App.SequenceAI_Create(pShip, "WaitThenAttack")
	pWaitThenAttack.SetInterruptable(1)
	pWaitThenAttack.SetLoopCount(1)
	pWaitThenAttack.SetResetIfInterrupted(1)
	pWaitThenAttack.SetDoubleCheckAllDone(0)
	pWaitThenAttack.SetSkipDormant(0)
	# SeqBlock is at (337, 204)
	pWaitThenAttack.AddAI(pDelay)
	pWaitThenAttack.AddAI(pAttack)
	# Done creating SequenceAI WaitThenAttack
	#########################################
	#########################################
	# Creating PlainAI Stay at (316, 149)
	pStay = App.PlainAI_Create(pShip, "Stay")
	pStay.SetScriptModule("Stay")
	pStay.SetInterruptable(1)
	# Done creating PlainAI Stay
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (218, 119)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (192, 156)
	pPriorityList.AddAI(pStationDead, 1)
	pPriorityList.AddAI(pPlayerNotInSB12, 2)
	pPriorityList.AddAI(pWaitThenAttack, 3)
	pPriorityList.AddAI(pStay, 4)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (218, 76)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pPriorityList)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	#########################################
	# Creating PreprocessingAI RedAlert at (217, 28)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AlertLevel(App.ShipClass.RED_ALERT)
	## The PreprocessingAI:
	pRedAlert = App.PreprocessingAI_Create(pShip, "RedAlert")
	pRedAlert.SetInterruptable(1)
	pRedAlert.SetPreprocessingMethod(pScript, "Update")
	pRedAlert.SetContainedAI(pAvoidObstacles)
	# Done creating PreprocessingAI RedAlert
	#########################################
	return pRedAlert
