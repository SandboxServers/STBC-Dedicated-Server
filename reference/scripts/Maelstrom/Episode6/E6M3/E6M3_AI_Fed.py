import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI WarpToSavoy3 at (32, 116)
	pWarpToSavoy3 = App.PlainAI_Create(pShip, "WarpToSavoy3")
	pWarpToSavoy3.SetScriptModule("Warp")
	pWarpToSavoy3.SetInterruptable(0)
	pScript = pWarpToSavoy3.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.Savoy.Savoy3")
	pScript.SetDestinationPlacementName("FedEnter")
	pScript.SetWarpDuration(2)
	# Done creating PlainAI WarpToSavoy3
	#########################################
	#########################################
	# Creating PlainAI InterceptGalor1 at (77, 17)
	pInterceptGalor1 = App.PlainAI_Create(pShip, "InterceptGalor1")
	pInterceptGalor1.SetScriptModule("Intercept")
	pInterceptGalor1.SetInterruptable(1)
	pScript = pInterceptGalor1.GetScriptInstance()
	pScript.SetTargetObjectName("Galor 1")
	pScript.SetMaximumSpeed(10)
	pScript.SetInterceptDistance(10)
	# Done creating PlainAI InterceptGalor1
	#########################################
	#########################################
	# Creating ConditionalAI TargetsNotInRange at (88, 64)
	## Conditions:
	#### Condition GalorsInRange
	pGalorsInRange = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 200, pShip.GetName(), "Galor 1", "Galor 2")
	## Evaluation function:
	def EvalFunc(bGalorsInRange):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bGalorsInRange):
			return DONE
		return ACTIVE
	## The ConditionalAI:
	pTargetsNotInRange = App.ConditionalAI_Create(pShip, "TargetsNotInRange")
	pTargetsNotInRange.SetInterruptable(1)
	pTargetsNotInRange.SetContainedAI(pInterceptGalor1)
	pTargetsNotInRange.AddCondition(pGalorsInRange)
	pTargetsNotInRange.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI TargetsNotInRange
	#########################################
	#########################################
	# Creating PlainAI Stay at (195, 23)
	pStay = App.PlainAI_Create(pShip, "Stay")
	pStay.SetScriptModule("Stay")
	pStay.SetInterruptable(1)
	# Done creating PlainAI Stay
	#########################################
	#########################################
	# Creating ConditionalAI IsPlayerInSet at (177, 87)
	## Conditions:
	#### Condition PlayerInSet
	pPlayerInSet = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", "player", "Savoy3")
	## Evaluation function:
	def EvalFunc(bPlayerInSet):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bPlayerInSet):
			return DONE
		return ACTIVE
	## The ConditionalAI:
	pIsPlayerInSet = App.ConditionalAI_Create(pShip, "IsPlayerInSet")
	pIsPlayerInSet.SetInterruptable(1)
	pIsPlayerInSet.SetContainedAI(pStay)
	pIsPlayerInSet.AddCondition(pPlayerInSet)
	pIsPlayerInSet.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI IsPlayerInSet
	#########################################
	#########################################
	# Creating CompoundAI BasicAttack3pSavoy3FedsTargets at (238, 129)
	import AI.Compound.BasicAttack
	pBasicAttack3pSavoy3FedsTargets = AI.Compound.BasicAttack.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode6.E6M3.E6M3", "g_pSavoy3FedsTargets"), Difficulty = 0.75, SmartTorpSelection = 0)
	# Done creating CompoundAI BasicAttack3pSavoy3FedsTargets
	#########################################
	#########################################
	# Creating PlainAI WarpToSavoy1 at (335, 61)
	pWarpToSavoy1 = App.PlainAI_Create(pShip, "WarpToSavoy1")
	pWarpToSavoy1.SetScriptModule("Warp")
	pWarpToSavoy1.SetInterruptable(1)
	pScript = pWarpToSavoy1.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.Savoy.Savoy1")
	pScript.SetDestinationPlacementName("FedEnter")
	pScript.SetWarpDuration(15)
	# Done creating PlainAI WarpToSavoy1
	#########################################
	#########################################
	# Creating ConditionalAI WarpTimer at (331, 117)
	## Conditions:
	#### Condition Timer
	pTimer = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 15)
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
	pWarpTimer.SetContainedAI(pWarpToSavoy1)
	pWarpTimer.AddCondition(pTimer)
	pWarpTimer.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI WarpTimer
	#########################################
	#########################################
	# Creating PlainAI Call_ThisShipDamaged at (462, 45)
	pCall_ThisShipDamaged = App.PlainAI_Create(pShip, "Call_ThisShipDamaged")
	pCall_ThisShipDamaged.SetScriptModule("RunScript")
	pCall_ThisShipDamaged.SetInterruptable(1)
	pScript = pCall_ThisShipDamaged.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode6.E6M3.E6M3")
	pScript.SetFunction("FedShipDamaged")
	pScript.SetArguments(pShip.GetName())
	# Done creating PlainAI Call_ThisShipDamaged
	#########################################
	#########################################
	# Creating ConditionalAI TakingHullDamage at (458, 107)
	## Conditions:
	#### Condition HullAt75
	pHullAt75 = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName(), App.CT_HULL_SUBSYSTEM, 0.75)
	## Evaluation function:
	def EvalFunc(bHullAt75):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bHullAt75):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pTakingHullDamage = App.ConditionalAI_Create(pShip, "TakingHullDamage")
	pTakingHullDamage.SetInterruptable(1)
	pTakingHullDamage.SetContainedAI(pCall_ThisShipDamaged)
	pTakingHullDamage.AddCondition(pHullAt75)
	pTakingHullDamage.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI TakingHullDamage
	#########################################
	#########################################
	# Creating CompoundAI BasicAttackTransports at (559, 47)
	import AI.Compound.BasicAttack
	pBasicAttackTransports = AI.Compound.BasicAttack.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode6.E6M3.E6M3", "g_pSavoy1Transports"), Difficulty = 0.01, SmartTorpSelection = 0)
	# Done creating CompoundAI BasicAttackTransports
	#########################################
	#########################################
	# Creating ConditionalAI TransportCloseToStation at (551, 108)
	## Conditions:
	#### Condition Transport80kFromStation
	pTransport80kFromStation = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 450, "Savoy Station", "Transport 1", "Transport 2")
	## Evaluation function:
	def EvalFunc(bTransport80kFromStation):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bTransport80kFromStation):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pTransportCloseToStation = App.ConditionalAI_Create(pShip, "TransportCloseToStation")
	pTransportCloseToStation.SetInterruptable(1)
	pTransportCloseToStation.SetContainedAI(pBasicAttackTransports)
	pTransportCloseToStation.AddCondition(pTransport80kFromStation)
	pTransportCloseToStation.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI TransportCloseToStation
	#########################################
	#########################################
	# Creating CompoundAI BasicAttack3Savoy1FedsTargets at (680, 42)
	import AI.Compound.BasicAttack
	pBasicAttack3Savoy1FedsTargets = AI.Compound.BasicAttack.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode6.E6M3.E6M3", "g_pSavoy1FedsTargets"), Difficulty = 0.75, SmartTorpSelection = 0)
	# Done creating CompoundAI BasicAttack3Savoy1FedsTargets
	#########################################
	#########################################
	# Creating CompoundAI BasicAttackSavoy1Transports at (674, 108)
	import AI.Compound.BasicAttack
	pBasicAttackSavoy1Transports = AI.Compound.BasicAttack.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode6.E6M3.E6M3", "g_pSavoy1Transports"), Difficulty = 0.75, SmartTorpSelection = 0)
	# Done creating CompoundAI BasicAttackSavoy1Transports
	#########################################
	#########################################
	# Creating PlainAI FollowKhitomer at (647, 187)
	pFollowKhitomer = App.PlainAI_Create(pShip, "FollowKhitomer")
	pFollowKhitomer.SetScriptModule("FollowObject")
	pFollowKhitomer.SetInterruptable(1)
	pScript = pFollowKhitomer.GetScriptInstance()
	pScript.SetFollowObjectName("Khitomer")
	pScript.SetRoughDistances(150, 175, 200)
	# Done creating PlainAI FollowKhitomer
	#########################################
	#########################################
	# Creating PriorityListAI Savoy1Priority at (404, 183)
	pSavoy1Priority = App.PriorityListAI_Create(pShip, "Savoy1Priority")
	pSavoy1Priority.SetInterruptable(1)
	# SeqBlock is at (530, 192)
	pSavoy1Priority.AddAI(pTakingHullDamage, 1)
	pSavoy1Priority.AddAI(pTransportCloseToStation, 2)
	pSavoy1Priority.AddAI(pBasicAttack3Savoy1FedsTargets, 3)
	pSavoy1Priority.AddAI(pBasicAttackSavoy1Transports, 4)
	pSavoy1Priority.AddAI(pFollowKhitomer, 5)
	# Done creating PriorityListAI Savoy1Priority
	#########################################
	#########################################
	# Creating SequenceAI InnerSequence at (233, 181)
	pInnerSequence = App.SequenceAI_Create(pShip, "InnerSequence")
	pInnerSequence.SetInterruptable(1)
	pInnerSequence.SetLoopCount(1)
	pInnerSequence.SetResetIfInterrupted(0)
	pInnerSequence.SetDoubleCheckAllDone(0)
	pInnerSequence.SetSkipDormant(0)
	# SeqBlock is at (347, 188)
	pInnerSequence.AddAI(pWarpTimer)
	pInnerSequence.AddAI(pSavoy1Priority)
	# Done creating SequenceAI InnerSequence
	#########################################
	#########################################
	# Creating SequenceAI Savoy3Sequence at (13, 190)
	pSavoy3Sequence = App.SequenceAI_Create(pShip, "Savoy3Sequence")
	pSavoy3Sequence.SetInterruptable(1)
	pSavoy3Sequence.SetLoopCount(1)
	pSavoy3Sequence.SetResetIfInterrupted(0)
	pSavoy3Sequence.SetDoubleCheckAllDone(0)
	pSavoy3Sequence.SetSkipDormant(1)
	# SeqBlock is at (133, 191)
	pSavoy3Sequence.AddAI(pWarpToSavoy3)
	pSavoy3Sequence.AddAI(pTargetsNotInRange)
	pSavoy3Sequence.AddAI(pIsPlayerInSet)
	pSavoy3Sequence.AddAI(pBasicAttack3pSavoy3FedsTargets)
	pSavoy3Sequence.AddAI(pInnerSequence)
	# Done creating SequenceAI Savoy3Sequence
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (10, 256)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pSavoy3Sequence)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
