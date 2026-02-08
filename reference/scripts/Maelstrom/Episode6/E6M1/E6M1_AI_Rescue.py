import App
def CreateAI(pShip, pTargetGroup):

	#########################################
	# Creating PlainAI WarpToSavoy3 at (21, 21)
	pWarpToSavoy3 = App.PlainAI_Create(pShip, "WarpToSavoy3")
	pWarpToSavoy3.SetScriptModule("Warp")
	pWarpToSavoy3.SetInterruptable(1)
	pScript = pWarpToSavoy3.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.Savoy.Savoy3")
	pScript.SetDestinationPlacementName("DevoreEnter")
	pScript.SetWarpDuration(10)
	# Done creating PlainAI WarpToSavoy3
	#########################################
	#########################################
	# Creating PlainAI Call_RescueWarping at (160, 47)
	pCall_RescueWarping = App.PlainAI_Create(pShip, "Call_RescueWarping")
	pCall_RescueWarping.SetScriptModule("RunScript")
	pCall_RescueWarping.SetInterruptable(1)
	pScript = pCall_RescueWarping.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode6.E6M1.E6M1")
	pScript.SetFunction("RescueWarping")
	# Done creating PlainAI Call_RescueWarping
	#########################################
	#########################################
	# Creating ConditionalAI WarpTimer at (100, 93)
	## Conditions:
	#### Condition Timer
	pTimer = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 3)
	## Evaluation function:
	def EvalFunc(bTimer):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bTimer):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pWarpTimer = App.ConditionalAI_Create(pShip, "WarpTimer")
	pWarpTimer.SetInterruptable(1)
	pWarpTimer.SetContainedAI(pCall_RescueWarping)
	pWarpTimer.AddCondition(pTimer)
	pWarpTimer.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI WarpTimer
	#########################################
	#########################################
	# Creating ConditionalAI PlayerinSavoy3 at (41, 139)
	## Conditions:
	#### Condition PlayerinSavoy3Set
	pPlayerinSavoy3Set = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", "player", "Savoy3")
	## Evaluation function:
	def EvalFunc(bPlayerinSavoy3Set):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bPlayerinSavoy3Set):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pPlayerinSavoy3 = App.ConditionalAI_Create(pShip, "PlayerinSavoy3")
	pPlayerinSavoy3.SetInterruptable(1)
	pPlayerinSavoy3.SetContainedAI(pWarpTimer)
	pPlayerinSavoy3.AddCondition(pPlayerinSavoy3Set)
	pPlayerinSavoy3.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI PlayerinSavoy3
	#########################################
	#########################################
	# Creating PlainAI WarpToSavoy1 at (61, 189)
	pWarpToSavoy1 = App.PlainAI_Create(pShip, "WarpToSavoy1")
	pWarpToSavoy1.SetScriptModule("Warp")
	pWarpToSavoy1.SetInterruptable(1)
	pScript = pWarpToSavoy1.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.Savoy.Savoy1")
	pScript.SetDestinationPlacementName("DevoreEnter")
	pScript.SetWarpDuration(10)
	# Done creating PlainAI WarpToSavoy1
	#########################################
	#########################################
	# Creating PlainAI Call_RescueTakingDamage at (159, 148)
	pCall_RescueTakingDamage = App.PlainAI_Create(pShip, "Call_RescueTakingDamage")
	pCall_RescueTakingDamage.SetScriptModule("RunScript")
	pCall_RescueTakingDamage.SetInterruptable(1)
	pScript = pCall_RescueTakingDamage.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode6.E6M1.E6M1")
	pScript.SetFunction("RescueTakingDamage")
	# Done creating PlainAI Call_RescueTakingDamage
	#########################################
	#########################################
	# Creating ConditionalAI HullTakingDamage at (159, 204)
	## Conditions:
	#### Condition HullAt80
	pHullAt80 = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName(), App.CT_HULL_SUBSYSTEM, 0.80)
	## Evaluation function:
	def EvalFunc(bHullAt80):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bHullAt80):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pHullTakingDamage = App.ConditionalAI_Create(pShip, "HullTakingDamage")
	pHullTakingDamage.SetInterruptable(1)
	pHullTakingDamage.SetContainedAI(pCall_RescueTakingDamage)
	pHullTakingDamage.AddCondition(pHullAt80)
	pHullTakingDamage.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI HullTakingDamage
	#########################################
	#########################################
	# Creating PlainAI Call_RescueCallsForHelp at (255, 153)
	pCall_RescueCallsForHelp = App.PlainAI_Create(pShip, "Call_RescueCallsForHelp")
	pCall_RescueCallsForHelp.SetScriptModule("RunScript")
	pCall_RescueCallsForHelp.SetInterruptable(1)
	pScript = pCall_RescueCallsForHelp.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode6.E6M1.E6M1")
	pScript.SetFunction("RescueCallsForHelp")
	# Done creating PlainAI Call_RescueCallsForHelp
	#########################################
	#########################################
	# Creating ConditionalAI CardsArriveSavoy1 at (260, 205)
	## Conditions:
	#### Condition CardsInSet
	pCardsInSet = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", "Galor 12", "Savoy1")
	#### Condition GalorInSet
	pGalorInSet = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", "Galor 11", "Savoy1")
	#### Condition KeldonInSet
	pKeldonInSet = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", "Keldon 5", "Savoy 1")
	#### Condition OtherKeldonInSet
	pOtherKeldonInSet = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", "Keldon 4", "Savoy 1")
	#### Condition OtherGalorInSet
	pOtherGalorInSet = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", "Galor 10", "Savoy 1")
	## Evaluation function:
	def EvalFunc(bCardsInSet, bGalorInSet, bKeldonInSet, bOtherKeldonInSet, bOtherGalorInSet):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bCardsInSet) or (bGalorInSet) or (bKeldonInSet) or (bOtherKeldonInSet) or (bOtherGalorInSet):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pCardsArriveSavoy1 = App.ConditionalAI_Create(pShip, "CardsArriveSavoy1")
	pCardsArriveSavoy1.SetInterruptable(1)
	pCardsArriveSavoy1.SetContainedAI(pCall_RescueCallsForHelp)
	pCardsArriveSavoy1.AddCondition(pCardsInSet)
	pCardsArriveSavoy1.AddCondition(pGalorInSet)
	pCardsArriveSavoy1.AddCondition(pKeldonInSet)
	pCardsArriveSavoy1.AddCondition(pOtherKeldonInSet)
	pCardsArriveSavoy1.AddCondition(pOtherGalorInSet)
	pCardsArriveSavoy1.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI CardsArriveSavoy1
	#########################################
	#########################################
	# Creating PlainAI FlyToStation at (353, 151)
	pFlyToStation = App.PlainAI_Create(pShip, "FlyToStation")
	pFlyToStation.SetScriptModule("Intercept")
	pFlyToStation.SetInterruptable(1)
	pScript = pFlyToStation.GetScriptInstance()
	pScript.SetTargetObjectName("Savoy Station")
	pScript.SetMaximumSpeed(10)
	pScript.SetInterceptDistance(50)
	# Done creating PlainAI FlyToStation
	#########################################
	#########################################
	# Creating ConditionalAI NotCloseToStation at (352, 202)
	## Conditions:
	#### Condition StationInRange
	pStationInRange = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 70,pShip.GetName(),  "Savoy Station")
	## Evaluation function:
	def EvalFunc(bStationInRange):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bStationInRange):
			return DONE
		return ACTIVE
	## The ConditionalAI:
	pNotCloseToStation = App.ConditionalAI_Create(pShip, "NotCloseToStation")
	pNotCloseToStation.SetInterruptable(1)
	pNotCloseToStation.SetContainedAI(pFlyToStation)
	pNotCloseToStation.AddCondition(pStationInRange)
	pNotCloseToStation.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI NotCloseToStation
	#########################################
	#########################################
	# Creating PlainAI Call_RescueAtStation at (450, 137)
	pCall_RescueAtStation = App.PlainAI_Create(pShip, "Call_RescueAtStation")
	pCall_RescueAtStation.SetScriptModule("RunScript")
	pCall_RescueAtStation.SetInterruptable(1)
	pScript = pCall_RescueAtStation.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode6.E6M1.E6M1")
	pScript.SetFunction("RescueAtStation")
	# Done creating PlainAI Call_RescueAtStation
	#########################################
	#########################################
	# Creating ConditionalAI CloseToStation at (453, 190)
	## Conditions:
	#### Condition RescueCloseToStation
	pRescueCloseToStation = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 80, pShip.GetName(), "Savoy Station")
	## Evaluation function:
	def EvalFunc(bRescueCloseToStation):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bRescueCloseToStation):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pCloseToStation = App.ConditionalAI_Create(pShip, "CloseToStation")
	pCloseToStation.SetInterruptable(1)
	pCloseToStation.SetContainedAI(pCall_RescueAtStation)
	pCloseToStation.AddCondition(pRescueCloseToStation)
	pCloseToStation.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI CloseToStation
	#########################################
	#########################################
	# Creating CompoundAI BasicAttack at (474, 246)
	import AI.Compound.BasicAttack
	pBasicAttack = AI.Compound.BasicAttack.CreateAI(pShip, pTargetGroup, Difficulty = 0.75, SmartTorpSelection = 0)
	# Done creating CompoundAI BasicAttack
	#########################################
	#########################################
	# Creating PlainAI OrbitStation at (510, 335)
	pOrbitStation = App.PlainAI_Create(pShip, "OrbitStation")
	pOrbitStation.SetScriptModule("CircleObject")
	pOrbitStation.SetInterruptable(1)
	pScript = pOrbitStation.GetScriptInstance()
	pScript.SetFollowObjectName("Savoy Station")
	pScript.SetNearFacingVector(App.TGPoint3_GetModelRight())
	pScript.SetRoughDistances(40, 60)
	pScript.SetCircleSpeed(0.5)
	# Done creating PlainAI OrbitStation
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (137, 290)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (353, 295)
	pPriorityList.AddAI(pHullTakingDamage, 1)
	pPriorityList.AddAI(pCardsArriveSavoy1, 2)
	pPriorityList.AddAI(pNotCloseToStation, 3)
	pPriorityList.AddAI(pCloseToStation, 4)
	pPriorityList.AddAI(pBasicAttack, 5)
	pPriorityList.AddAI(pOrbitStation, 6)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating SequenceAI MainSequence at (21, 302)
	pMainSequence = App.SequenceAI_Create(pShip, "MainSequence")
	pMainSequence.SetInterruptable(1)
	pMainSequence.SetLoopCount(1)
	pMainSequence.SetResetIfInterrupted(1)
	pMainSequence.SetDoubleCheckAllDone(0)
	pMainSequence.SetSkipDormant(0)
	# SeqBlock is at (21, 257)
	pMainSequence.AddAI(pWarpToSavoy3)
	pMainSequence.AddAI(pPlayerinSavoy3)
	pMainSequence.AddAI(pWarpToSavoy1)
	pMainSequence.AddAI(pPriorityList)
	# Done creating SequenceAI MainSequence
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (22, 350)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pMainSequence)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
