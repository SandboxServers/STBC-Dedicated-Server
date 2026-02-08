import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI WarpToTezle2 at (6, 270)
	pWarpToTezle2 = App.PlainAI_Create(pShip, "WarpToTezle2")
	pWarpToTezle2.SetScriptModule("Warp")
	pWarpToTezle2.SetInterruptable(1)
	pScript = pWarpToTezle2.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.Tezle.Tezle2")
	pScript.SetDestinationPlacementName("KhitEnter")
	pScript.SetWarpDuration(1)
	pScript.WarpBlindly(1)
	# Done creating PlainAI WarpToTezle2
	#########################################
	#########################################
	# Creating PlainAI DefensiveFleeGalor3 at (6, 6)
	pDefensiveFleeGalor3 = App.PlainAI_Create(pShip, "DefensiveFleeGalor3")
	pDefensiveFleeGalor3.SetScriptModule("IntelligentCircleObject")
	pDefensiveFleeGalor3.SetInterruptable(1)
	pScript = pDefensiveFleeGalor3.GetScriptInstance()
	pScript.SetFollowObjectName("Galor 3")
	pScript.SetShieldAndWeaponImportance(0.8, 0.2)
	pScript.SetForwardBias(-0.5)
	# Done creating PlainAI DefensiveFleeGalor3
	#########################################
	#########################################
	# Creating ConditionalAI Galor3Attack at (6, 59)
	## Conditions:
	#### Condition AttackedByGalor3
	pAttackedByGalor3 = App.ConditionScript_Create("Conditions.ConditionAttackedBy", "ConditionAttackedBy", pShip.GetName(), "Galor 3", 0.20, 0, 120)
	## Evaluation function:
	def EvalFunc(bAttackedByGalor3):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bAttackedByGalor3):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pGalor3Attack = App.ConditionalAI_Create(pShip, "Galor3Attack")
	pGalor3Attack.SetInterruptable(1)
	pGalor3Attack.SetContainedAI(pDefensiveFleeGalor3)
	pGalor3Attack.AddCondition(pAttackedByGalor3)
	pGalor3Attack.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI Galor3Attack
	#########################################
	#########################################
	# Creating PlainAI DefensiveFleeGalor4 at (91, 7)
	pDefensiveFleeGalor4 = App.PlainAI_Create(pShip, "DefensiveFleeGalor4")
	pDefensiveFleeGalor4.SetScriptModule("IntelligentCircleObject")
	pDefensiveFleeGalor4.SetInterruptable(1)
	pScript = pDefensiveFleeGalor4.GetScriptInstance()
	pScript.SetFollowObjectName("Galor 4")
	pScript.SetShieldAndWeaponImportance(0.8, 0.2)
	pScript.SetForwardBias(-0.5)
	# Done creating PlainAI DefensiveFleeGalor4
	#########################################
	#########################################
	# Creating ConditionalAI Galor4Attack at (91, 54)
	## Conditions:
	#### Condition AttackedByGalor4
	pAttackedByGalor4 = App.ConditionScript_Create("Conditions.ConditionAttackedBy", "ConditionAttackedBy", pShip.GetName(), "Galor 4", 0.20, 0, 120)
	## Evaluation function:
	def EvalFunc(bAttackedByGalor4):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bAttackedByGalor4):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pGalor4Attack = App.ConditionalAI_Create(pShip, "Galor4Attack")
	pGalor4Attack.SetInterruptable(1)
	pGalor4Attack.SetContainedAI(pDefensiveFleeGalor4)
	pGalor4Attack.AddCondition(pAttackedByGalor4)
	pGalor4Attack.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI Galor4Attack
	#########################################
	#########################################
	# Creating PlainAI DefensiveFleeGalor1 at (185, 3)
	pDefensiveFleeGalor1 = App.PlainAI_Create(pShip, "DefensiveFleeGalor1")
	pDefensiveFleeGalor1.SetScriptModule("IntelligentCircleObject")
	pDefensiveFleeGalor1.SetInterruptable(1)
	pScript = pDefensiveFleeGalor1.GetScriptInstance()
	pScript.SetFollowObjectName("Galor 1")
	pScript.SetShieldAndWeaponImportance(0.8, 0.2)
	pScript.SetForwardBias(-0.5)
	# Done creating PlainAI DefensiveFleeGalor1
	#########################################
	#########################################
	# Creating ConditionalAI Galor1Attack at (185, 58)
	## Conditions:
	#### Condition AttackedByGalor1
	pAttackedByGalor1 = App.ConditionScript_Create("Conditions.ConditionAttackedBy", "ConditionAttackedBy", pShip.GetName(), "Galor 1", 0.20, 0, 120)
	## Evaluation function:
	def EvalFunc(bAttackedByGalor1):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bAttackedByGalor1):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pGalor1Attack = App.ConditionalAI_Create(pShip, "Galor1Attack")
	pGalor1Attack.SetInterruptable(1)
	pGalor1Attack.SetContainedAI(pDefensiveFleeGalor1)
	pGalor1Attack.AddCondition(pAttackedByGalor1)
	pGalor1Attack.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI Galor1Attack
	#########################################
	#########################################
	# Creating PlainAI DefensiveFleeGalor2 at (279, 10)
	pDefensiveFleeGalor2 = App.PlainAI_Create(pShip, "DefensiveFleeGalor2")
	pDefensiveFleeGalor2.SetScriptModule("IntelligentCircleObject")
	pDefensiveFleeGalor2.SetInterruptable(1)
	pScript = pDefensiveFleeGalor2.GetScriptInstance()
	pScript.SetFollowObjectName("Galor 2")
	pScript.SetShieldAndWeaponImportance(0.8, 0.2)
	pScript.SetForwardBias(-0.5)
	# Done creating PlainAI DefensiveFleeGalor2
	#########################################
	#########################################
	# Creating ConditionalAI Galor2Attack at (275, 61)
	## Conditions:
	#### Condition AttackedByGalor2
	pAttackedByGalor2 = App.ConditionScript_Create("Conditions.ConditionAttackedBy", "ConditionAttackedBy", pShip.GetName(), "Galor 2", 0.20, 0, 120)
	## Evaluation function:
	def EvalFunc(bAttackedByGalor2):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bAttackedByGalor2):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pGalor2Attack = App.ConditionalAI_Create(pShip, "Galor2Attack")
	pGalor2Attack.SetInterruptable(1)
	pGalor2Attack.SetContainedAI(pDefensiveFleeGalor2)
	pGalor2Attack.AddCondition(pAttackedByGalor2)
	pGalor2Attack.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI Galor2Attack
	#########################################
	#########################################
	# Creating CompoundAI BasicAttack4FedTezle2Targets at (258, 136)
	import AI.Compound.BasicAttack
	pBasicAttack4FedTezle2Targets = AI.Compound.BasicAttack.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode6.E6M5.E6M5", "g_pFedTezle2Targets"), Easy_Difficulty = 1.0, Difficulty = 0.7, Hard_Difficulty = 0.77)
	# Done creating CompoundAI BasicAttack4FedTezle2Targets
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (107, 172)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (124, 140)
	pPriorityList.AddAI(pGalor3Attack, 1)
	pPriorityList.AddAI(pGalor4Attack, 2)
	pPriorityList.AddAI(pGalor1Attack, 3)
	pPriorityList.AddAI(pGalor2Attack, 4)
	pPriorityList.AddAI(pBasicAttack4FedTezle2Targets, 5)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating ConditionalAI EnemiesInSet at (92, 227)
	## Conditions:
	#### Condition CardsInSet
	pCardsInSet = App.ConditionScript_Create("Conditions.ConditionAnyInSameSet", "ConditionAnyInSameSet", pShip.GetName(), "Galor 3", "Galor 4", "Galor 1", "Galor 2", "Keldon 1")
	## Evaluation function:
	def EvalFunc(bCardsInSet):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if not bCardsInSet:
			return DONE
		return ACTIVE
	## The ConditionalAI:
	pEnemiesInSet = App.ConditionalAI_Create(pShip, "EnemiesInSet")
	pEnemiesInSet.SetInterruptable(1)
	pEnemiesInSet.SetContainedAI(pPriorityList)
	pEnemiesInSet.AddCondition(pCardsInSet)
	pEnemiesInSet.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI EnemiesInSet
	#########################################
	#########################################
	# Creating PlainAI CallTezle1Clear at (117, 275)
	pCallTezle1Clear = App.PlainAI_Create(pShip, "CallTezle1Clear")
	pCallTezle1Clear.SetScriptModule("RunScript")
	pCallTezle1Clear.SetInterruptable(1)
	pScript = pCallTezle1Clear.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode6.E6M5.E6M5")
	pScript.SetFunction("Tezle2Clear")
	# Done creating PlainAI CallTezle1Clear
	#########################################
	#########################################
	# Creating PlainAI WarpToTezle1 at (205, 275)
	pWarpToTezle1 = App.PlainAI_Create(pShip, "WarpToTezle1")
	pWarpToTezle1.SetScriptModule("Warp")
	pWarpToTezle1.SetInterruptable(1)
	pScript = pWarpToTezle1.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.Tezle.Tezle1")
	pScript.SetDestinationPlacementName("KhitEnter")
	pScript.SetWarpDuration(10)
	# Done creating PlainAI WarpToTezle1
	#########################################
	#########################################
	# Creating ConditionalAI WarpTimer at (192, 335)
	## Conditions:
	#### Condition Timer
	pTimer = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 20)
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
	pWarpTimer.SetContainedAI(pWarpToTezle1)
	pWarpTimer.AddCondition(pTimer)
	pWarpTimer.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI WarpTimer
	#########################################
	#########################################
	# Creating PlainAI Call_KhitLaunchingShuttles at (291, 205)
	pCall_KhitLaunchingShuttles = App.PlainAI_Create(pShip, "Call_KhitLaunchingShuttles")
	pCall_KhitLaunchingShuttles.SetScriptModule("RunScript")
	pCall_KhitLaunchingShuttles.SetInterruptable(1)
	pScript = pCall_KhitLaunchingShuttles.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode6.E6M5.E6M5")
	pScript.SetFunction("KhitLaunchingShuttles")
	# Done creating PlainAI Call_KhitLaunchingShuttles
	#########################################
	#########################################
	# Creating ConditionalAI Timer at (290, 252)
	## Conditions:
	#### Condition Timer5
	pTimer5 = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 5)
	## Evaluation function:
	def EvalFunc(bTimer5):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bTimer5:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pTimer = App.ConditionalAI_Create(pShip, "Timer")
	pTimer.SetInterruptable(1)
	pTimer.SetContainedAI(pCall_KhitLaunchingShuttles)
	pTimer.AddCondition(pTimer5)
	pTimer.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI Timer
	#########################################
	#########################################
	# Creating ConditionalAI CloseToPlanet at (287, 305)
	## Conditions:
	#### Condition PlanetInRange
	pPlanetInRange = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 300, pShip.GetName(), "Tezle 1")
	## Evaluation function:
	def EvalFunc(bPlanetInRange):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bPlanetInRange):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pCloseToPlanet = App.ConditionalAI_Create(pShip, "CloseToPlanet")
	pCloseToPlanet.SetInterruptable(1)
	pCloseToPlanet.SetContainedAI(pTimer)
	pCloseToPlanet.AddCondition(pPlanetInRange)
	pCloseToPlanet.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI CloseToPlanet
	#########################################
	#########################################
	# Creating PlainAI Orbit at (381, 124)
	pOrbit = App.PlainAI_Create(pShip, "Orbit")
	pOrbit.SetScriptModule("CircleObject")
	pOrbit.SetInterruptable(1)
	pScript = pOrbit.GetScriptInstance()
	pScript.SetFollowObjectName("Tezle 1")
	pScript.SetNearFacingVector(App.TGPoint3_GetModelRight())
	pScript.SetRoughDistances(200, 350)
	pScript.SetCircleSpeed(0.75)
	# Done creating PlainAI Orbit
	#########################################
	# The object to orbit shouldn't be changed by the SelectTarget preprocess.
	pOrbit.UnregisterExternalFunction("SetTarget", None)
	#########################################
	# Creating PreprocessingAI Fire at (384, 169)
	## Setup:
	import AI.Preprocessors
	pFireScript = AI.Preprocessors.FireScript("Keldon 1")
	for pSystem in [ pShip.GetTorpedoSystem(), pShip.GetPhaserSystem(), pShip.GetPulseWeaponSystem() ]:
		if pSystem:
			pFireScript.AddWeaponSystem( pSystem )
	## The PreprocessingAI:
	pFire = App.PreprocessingAI_Create(pShip, "Fire")
	pFire.SetInterruptable(1)
	pFire.SetPreprocessingMethod(pFireScript, "Update")
	pFire.SetContainedAI(pOrbit)
	# Done creating PreprocessingAI Fire
	#########################################
	#########################################
	# Creating PreprocessingAI SelectTarget at (385, 214)
	## Setup:
	import AI.Preprocessors
	pAllTargetsGroup = App.ObjectGroup()
	pAllTargetsGroup.AddName("Keldon 1")
	pAllTargetsGroup.AddName("Galor 4")
	pAllTargetsGroup.AddName("Keldon 2")
	pAllTargetsGroup.AddName("Hybrid 1")
	pAllTargetsGroup.AddName("Hybrid 2")
	pAllTargetsGroup.AddName("Hybrid 3")
	pAllTargetsGroup.AddName("Hybrid 4")
	pAllTargetsGroup.AddName("Hybrid 5")
	pAllTargetsGroup.AddName("Galor 5")
	pSelectionPreprocess = AI.Preprocessors.SelectTarget(pAllTargetsGroup)
	## The PreprocessingAI:
	pSelectTarget = App.PreprocessingAI_Create(pShip, "SelectTarget")
	pSelectTarget.SetInterruptable(1)
	pSelectTarget.SetPreprocessingMethod(pSelectionPreprocess, "Update")
	pSelectTarget.SetContainedAI(pFire)
	# Done creating PreprocessingAI SelectTarget
	#########################################
	#########################################
	# Creating PlainAI Orbit_NoTargets at (485, 255)
	pOrbit_NoTargets = App.PlainAI_Create(pShip, "Orbit_NoTargets")
	pOrbit_NoTargets.SetScriptModule("CircleObject")
	pOrbit_NoTargets.SetInterruptable(1)
	pScript = pOrbit_NoTargets.GetScriptInstance()
	pScript.SetFollowObjectName("Tezle 1")
	pScript.SetNearFacingVector(App.TGPoint3_GetModelRight())
	pScript.SetRoughDistances(200, 350)
	pScript.SetCircleSpeed(0.75)
	# Done creating PlainAI Orbit_NoTargets
	#########################################
	#########################################
	# Creating PriorityListAI OrbitPriorityList at (286, 369)
	pOrbitPriorityList = App.PriorityListAI_Create(pShip, "OrbitPriorityList")
	pOrbitPriorityList.SetInterruptable(1)
	# SeqBlock is at (389, 369)
	pOrbitPriorityList.AddAI(pCloseToPlanet, 1)
	pOrbitPriorityList.AddAI(pSelectTarget, 2)
	pOrbitPriorityList.AddAI(pOrbit_NoTargets, 3)
	# Done creating PriorityListAI OrbitPriorityList
	#########################################
	#########################################
	# Creating ConditionalAI PlayerInSet at (227, 412)
	## Conditions:
	#### Condition PlayerArrives
	pPlayerArrives = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", "player", "Tezle1")
	## Evaluation function:
	def EvalFunc(bPlayerArrives):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bPlayerArrives:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pPlayerInSet = App.ConditionalAI_Create(pShip, "PlayerInSet")
	pPlayerInSet.SetInterruptable(1)
	pPlayerInSet.SetContainedAI(pOrbitPriorityList)
	pPlayerInSet.AddCondition(pPlayerArrives)
	pPlayerInSet.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI PlayerInSet
	#########################################
	#########################################
	# Creating SequenceAI MainSequence at (4, 387)
	pMainSequence = App.SequenceAI_Create(pShip, "MainSequence")
	pMainSequence.SetInterruptable(1)
	pMainSequence.SetLoopCount(1)
	pMainSequence.SetResetIfInterrupted(1)
	pMainSequence.SetDoubleCheckAllDone(0)
	pMainSequence.SetSkipDormant(0)
	# SeqBlock is at (96, 386)
	pMainSequence.AddAI(pWarpToTezle2)
	pMainSequence.AddAI(pEnemiesInSet)
	pMainSequence.AddAI(pCallTezle1Clear)
	pMainSequence.AddAI(pWarpTimer)
	pMainSequence.AddAI(pPlayerInSet)
	# Done creating SequenceAI MainSequence
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (4, 436)
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
