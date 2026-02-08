import App

def CreateAI(pShip):
	#########################################
	# Creating PlainAI Call_RihaKessokRetreats at (35, 40)
	pCall_RihaKessokRetreats = App.PlainAI_Create(pShip, "Call_RihaKessokRetreats")
	pCall_RihaKessokRetreats.SetScriptModule("RunScript")
	pCall_RihaKessokRetreats.SetInterruptable(1)
	pScript = pCall_RihaKessokRetreats.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode6.E6M4.E6M4")
	pScript.SetFunction("RihaKessokRetreats")
	# Done creating PlainAI Call_RihaKessokRetreats
	#########################################
	#########################################
	# Creating PlainAI WarpOutToTezle2 at (130, 31)
	pWarpOutToTezle2 = App.PlainAI_Create(pShip, "WarpOutToTezle2")
	pWarpOutToTezle2.SetScriptModule("Warp")
	pWarpOutToTezle2.SetInterruptable(1)
	pScript = pWarpOutToTezle2.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.Tezle.Tezle2")
	pScript.SetDestinationPlacementName("KessokStart")
	# Done creating PlainAI WarpOutToTezle2
	#########################################
	#########################################
	# Creating SequenceAI WarpSequence at (14, 152)
	pWarpSequence = App.SequenceAI_Create(pShip, "WarpSequence")
	pWarpSequence.SetInterruptable(1)
	pWarpSequence.SetLoopCount(1)
	pWarpSequence.SetResetIfInterrupted(1)
	pWarpSequence.SetDoubleCheckAllDone(0)
	pWarpSequence.SetSkipDormant(0)
	# SeqBlock is at (104, 138)
	pWarpSequence.AddAI(pCall_RihaKessokRetreats)
	pWarpSequence.AddAI(pWarpOutToTezle2)
	# Done creating SequenceAI WarpSequence
	#########################################
	#########################################
	# Creating ConditionalAI TakingDamage at (66, 223)
	## Conditions:
	#### Condition CriticalDamage
	pCriticalDamage = App.ConditionScript_Create("Conditions.ConditionCriticalSystemBelow", "ConditionCriticalSystemBelow", pShip.GetName(), 0.8)
	## Evaluation function:
	def EvalFunc(bCriticalDamage):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bCriticalDamage:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pTakingDamage = App.ConditionalAI_Create(pShip, "TakingDamage")
	pTakingDamage.SetInterruptable(1)
	pTakingDamage.SetContainedAI(pWarpSequence)
	pTakingDamage.AddCondition(pCriticalDamage)
	pTakingDamage.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI TakingDamage
	#########################################
	#########################################
	# Creating CompoundAI BasicAttack at (209, 113)
	import AI.Compound.BasicAttack
	pBasicAttack = AI.Compound.BasicAttack.CreateAI(pShip, "player", Easy_Difficulty = 0.51, Easy_MaxFiringRange = 360.0, Difficulty = 1.0, MaxFiringRange = 356.0, WarpOutBeforeDying = 1, Hard_Difficulty = 1.0, Hard_MaxFiringRange = 348.0)
	# Done creating CompoundAI BasicAttack
	#########################################
	#########################################
	# Creating ConditionalAI PlayerAttacks at (163, 173)
	## Conditions:
	#### Condition PlayerClose
	pPlayerClose = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 375, pShip.GetName(), "player")
	#### Condition AttackedByPlayer
	pAttackedByPlayer = App.ConditionScript_Create("Conditions.ConditionAttackedBy", "ConditionAttackedBy", pShip.GetName(), "player", 0.01, 0.01, 99)
	## Evaluation function:
	def EvalFunc(bPlayerClose, bAttackedByPlayer):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bPlayerClose or bAttackedByPlayer:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pPlayerAttacks = App.ConditionalAI_Create(pShip, "PlayerAttacks")
	pPlayerAttacks.SetInterruptable(1)
	pPlayerAttacks.SetContainedAI(pBasicAttack)
	pPlayerAttacks.AddCondition(pPlayerClose)
	pPlayerAttacks.AddCondition(pAttackedByPlayer)
	pPlayerAttacks.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI PlayerAttacks
	#########################################
	#########################################
	# Creating PlainAI Call_KessokDetected at (271, 187)
	pCall_KessokDetected = App.PlainAI_Create(pShip, "Call_KessokDetected")
	pCall_KessokDetected.SetScriptModule("RunScript")
	pCall_KessokDetected.SetInterruptable(1)
	pScript = pCall_KessokDetected.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode6.E6M4.E6M4")
	pScript.SetFunction("ScanningRiha")
	# Done creating PlainAI Call_KessokDetected
	#########################################
	#########################################
	# Creating ConditionalAI PlayerDetects at (223, 234)
	## Conditions:
	#### Condition PlayerCloseEnough
	pPlayerCloseEnough = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 625, pShip.GetName(), "player")
	## Evaluation function:
	def EvalFunc(bPlayerCloseEnough):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bPlayerCloseEnough:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pPlayerDetects = App.ConditionalAI_Create(pShip, "PlayerDetects")
	pPlayerDetects.SetInterruptable(1)
	pPlayerDetects.SetContainedAI(pCall_KessokDetected)
	pPlayerDetects.AddCondition(pPlayerCloseEnough)
	pPlayerDetects.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI PlayerDetects
	#########################################
	#########################################
	# Creating PlainAI OrbitDerelict at (388, 228)
	pOrbitDerelict = App.PlainAI_Create(pShip, "OrbitDerelict")
	pOrbitDerelict.SetScriptModule("CircleObject")
	pOrbitDerelict.SetInterruptable(1)
	pScript = pOrbitDerelict.GetScriptInstance()
	pScript.SetFollowObjectName("Derelict")
	pScript.SetNearFacingVector(App.TGPoint3_GetModelRight())
	pScript.SetRoughDistances(fNearDistance = 15, fFarDistance = 30)
	pScript.SetCircleSpeed(fSpeed = 0.1)
	# Done creating PlainAI OrbitDerelict
	#########################################
	#########################################
	# Creating PreprocessingAI GreenAlert at (325, 278)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AlertLevel(App.ShipClass.GREEN_ALERT)
	## The PreprocessingAI:
	pGreenAlert = App.PreprocessingAI_Create(pShip, "GreenAlert")
	pGreenAlert.SetInterruptable(1)
	pGreenAlert.SetPreprocessingMethod(pScript, "Update")
	pGreenAlert.SetContainedAI(pOrbitDerelict)
	# Done creating PreprocessingAI GreenAlert
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (27, 305)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (167, 313)
	pPriorityList.AddAI(pTakingDamage, 1)
	pPriorityList.AddAI(pPlayerAttacks, 2)
	pPriorityList.AddAI(pPlayerDetects, 3)
	pPriorityList.AddAI(pGreenAlert, 4)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (24, 360)
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
	return pAvoidObstacles
