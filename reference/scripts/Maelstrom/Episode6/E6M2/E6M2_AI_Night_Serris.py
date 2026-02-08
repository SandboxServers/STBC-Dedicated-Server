import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI WarpToSerris3 at (47, 164)
	pWarpToSerris3 = App.PlainAI_Create(pShip, "WarpToSerris3")
	pWarpToSerris3.SetScriptModule("Warp")
	pWarpToSerris3.SetInterruptable(1)
	pScript = pWarpToSerris3.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.Serris.Serris3")
	pScript.SetDestinationPlacementName("NightEnter")
	pScript.SetWarpDuration(10)
	# Done creating PlainAI WarpToSerris3
	#########################################
	#########################################
	# Creating ConditionalAI FirstWarpTimer at (57, 235)
	## Conditions:
	#### Condition Timer
	pTimer = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 10)
	## Evaluation function:
	def EvalFunc(bTimer):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bTimer):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pFirstWarpTimer = App.ConditionalAI_Create(pShip, "FirstWarpTimer")
	pFirstWarpTimer.SetInterruptable(1)
	pFirstWarpTimer.SetContainedAI(pWarpToSerris3)
	pFirstWarpTimer.AddCondition(pTimer)
	pFirstWarpTimer.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI FirstWarpTimer
	#########################################
	#########################################
	# Creating PlainAI WarpToSerris1 at (148, 167)
	pWarpToSerris1 = App.PlainAI_Create(pShip, "WarpToSerris1")
	pWarpToSerris1.SetScriptModule("Warp")
	pWarpToSerris1.SetInterruptable(1)
	pScript = pWarpToSerris1.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.Serris.Serris1")
	pScript.SetDestinationPlacementName("NightEnter")
	pScript.SetWarpDuration(10)
	# Done creating PlainAI WarpToSerris1
	#########################################
	#########################################
	# Creating ConditionalAI PlayerInSerris at (143, 236)
	## Conditions:
	#### Condition PlayerInSerris1
	pPlayerInSerris1 = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", "player", "Serris1")
	#### Condition PlayerInSerris3
	pPlayerInSerris3 = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", "player", "Serris3")
	## Evaluation function:
	def EvalFunc(bPlayerInSerris1, bPlayerInSerris3):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bPlayerInSerris1 or bPlayerInSerris3):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pPlayerInSerris = App.ConditionalAI_Create(pShip, "PlayerInSerris")
	pPlayerInSerris.SetInterruptable(1)
	pPlayerInSerris.SetContainedAI(pWarpToSerris1)
	pPlayerInSerris.AddCondition(pPlayerInSerris1)
	pPlayerInSerris.AddCondition(pPlayerInSerris3)
	pPlayerInSerris.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI PlayerInSerris
	#########################################
	#########################################
	# Creating PlainAI FlyToDauntless at (236, 159)
	pFlyToDauntless = App.PlainAI_Create(pShip, "FlyToDauntless")
	pFlyToDauntless.SetScriptModule("Intercept")
	pFlyToDauntless.SetInterruptable(1)
	pScript = pFlyToDauntless.GetScriptInstance()
	pScript.SetTargetObjectName("Dauntless")
	pScript.SetMaximumSpeed(5)
	pScript.SetInterceptDistance(10)
	# Done creating PlainAI FlyToDauntless
	#########################################
	#########################################
	# Creating ConditionalAI DauntlessNotInRange at (240, 224)
	## Conditions:
	#### Condition DauntlessInRange
	pDauntlessInRange = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 50, "Nightingale", "Dauntless")
	## Evaluation function:
	def EvalFunc(bDauntlessInRange):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bDauntlessInRange):
			return DONE
		return ACTIVE
	## The ConditionalAI:
	pDauntlessNotInRange = App.ConditionalAI_Create(pShip, "DauntlessNotInRange")
	pDauntlessNotInRange.SetInterruptable(1)
	pDauntlessNotInRange.SetContainedAI(pFlyToDauntless)
	pDauntlessNotInRange.AddCondition(pDauntlessInRange)
	pDauntlessNotInRange.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI DauntlessNotInRange
	#########################################
	#########################################
	# Creating CompoundAI GetDauntlessPassengers at (272, 279)
	import Maelstrom.Episode6.E6M2.GettingDauntlessPassengers
	pGetDauntlessPassengers = Maelstrom.Episode6.E6M2.GettingDauntlessPassengers.CreateAI(pShip)
	# Done creating CompoundAI GetDauntlessPassengers
	#########################################
	#########################################
	# Creating SequenceAI SerrisSequence at (14, 342)
	pSerrisSequence = App.SequenceAI_Create(pShip, "SerrisSequence")
	pSerrisSequence.SetInterruptable(1)
	pSerrisSequence.SetLoopCount(1)
	pSerrisSequence.SetResetIfInterrupted(1)
	pSerrisSequence.SetDoubleCheckAllDone(1)
	pSerrisSequence.SetSkipDormant(0)
	# SeqBlock is at (215, 347)
	pSerrisSequence.AddAI(pFirstWarpTimer)
	pSerrisSequence.AddAI(pPlayerInSerris)
	pSerrisSequence.AddAI(pDauntlessNotInRange)
	pSerrisSequence.AddAI(pGetDauntlessPassengers)
	# Done creating SequenceAI SerrisSequence
	#########################################
	return pSerrisSequence
