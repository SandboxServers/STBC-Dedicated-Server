import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI WarpToSavoy3 at (5, 162)
	pWarpToSavoy3 = App.PlainAI_Create(pShip, "WarpToSavoy3")
	pWarpToSavoy3.SetScriptModule("Warp")
	pWarpToSavoy3.SetInterruptable(0)
	pScript = pWarpToSavoy3.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.Savoy.Savoy3")
	pScript.SetDestinationPlacementName("KhitEnter")
	pScript.SetWarpDuration(1)
	# Done creating PlainAI WarpToSavoy3
	#########################################
	#########################################
	# Creating PlainAI InterceptGalor1 at (89, 55)
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
	# Creating ConditionalAI TargetsNotInRange at (72, 103)
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
	# Creating CompoundAI BasicAttack3pSavoy3FedsTargets at (162, 105)
	import AI.Compound.BasicAttack
	pBasicAttack3pSavoy3FedsTargets = AI.Compound.BasicAttack.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode6.E6M3.E6M3", "g_pSavoy3FedsTargets"), Difficulty = 0.63)
	# Done creating CompoundAI BasicAttack3pSavoy3FedsTargets
	#########################################
	#########################################
	# Creating PlainAI Call_WillisSayGoToSavoy1 at (281, 95)
	pCall_WillisSayGoToSavoy1 = App.PlainAI_Create(pShip, "Call_WillisSayGoToSavoy1")
	pCall_WillisSayGoToSavoy1.SetScriptModule("RunScript")
	pCall_WillisSayGoToSavoy1.SetInterruptable(1)
	pScript = pCall_WillisSayGoToSavoy1.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode6.E6M3.E6M3")
	pScript.SetFunction("WillisSayGoToSavoy1")
	# Done creating PlainAI Call_WillisSayGoToSavoy1
	#########################################
	#########################################
	# Creating PlainAI WarpToSavoy1 at (380, 79)
	pWarpToSavoy1 = App.PlainAI_Create(pShip, "WarpToSavoy1")
	pWarpToSavoy1.SetScriptModule("Warp")
	pWarpToSavoy1.SetInterruptable(1)
	pScript = pWarpToSavoy1.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.Savoy.Savoy1")
	pScript.SetDestinationPlacementName("KhitEnter")
	pScript.SetWarpDuration(15)
	# Done creating PlainAI WarpToSavoy1
	#########################################
	#########################################
	# Creating ConditionalAI WarpTimer at (373, 136)
	## Conditions:
	#### Condition Timer
	pTimer = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 22)
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
	# Creating SequenceAI WarpSequence at (224, 212)
	pWarpSequence = App.SequenceAI_Create(pShip, "WarpSequence")
	pWarpSequence.SetInterruptable(1)
	pWarpSequence.SetLoopCount(1)
	pWarpSequence.SetResetIfInterrupted(1)
	pWarpSequence.SetDoubleCheckAllDone(0)
	pWarpSequence.SetSkipDormant(0)
	# SeqBlock is at (327, 196)
	pWarpSequence.AddAI(pCall_WillisSayGoToSavoy1)
	pWarpSequence.AddAI(pWarpTimer)
	# Done creating SequenceAI WarpSequence
	#########################################
	#########################################
	# Creating SequenceAI Savoy3Sequence at (19, 237)
	pSavoy3Sequence = App.SequenceAI_Create(pShip, "Savoy3Sequence")
	pSavoy3Sequence.SetInterruptable(1)
	pSavoy3Sequence.SetLoopCount(1)
	pSavoy3Sequence.SetResetIfInterrupted(1)
	pSavoy3Sequence.SetDoubleCheckAllDone(0)
	pSavoy3Sequence.SetSkipDormant(1)
	# SeqBlock is at (119, 221)
	pSavoy3Sequence.AddAI(pWarpToSavoy3)
	pSavoy3Sequence.AddAI(pTargetsNotInRange)
	pSavoy3Sequence.AddAI(pBasicAttack3pSavoy3FedsTargets)
	pSavoy3Sequence.AddAI(pWarpSequence)
	# Done creating SequenceAI Savoy3Sequence
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (20, 295)
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
	#########################################
	# Creating PlainAI Call_KhitomerTakingDamage at (210, 331)
	pCall_KhitomerTakingDamage = App.PlainAI_Create(pShip, "Call_KhitomerTakingDamage")
	pCall_KhitomerTakingDamage.SetScriptModule("RunScript")
	pCall_KhitomerTakingDamage.SetInterruptable(1)
	pScript = pCall_KhitomerTakingDamage.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode6.E6M3.E6M3")
	pScript.SetFunction("KhitomerTakingDamage")
	# Done creating PlainAI Call_KhitomerTakingDamage
	#########################################
	#########################################
	# Creating ConditionalAI HullTakingDamage at (219, 385)
	## Conditions:
	#### Condition HullAt99
	pHullAt99 = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName(), App.CT_HULL_SUBSYSTEM, 0.90)
	## Evaluation function:
	def EvalFunc(bHullAt99):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bHullAt99):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pHullTakingDamage = App.ConditionalAI_Create(pShip, "HullTakingDamage")
	pHullTakingDamage.SetInterruptable(1)
	pHullTakingDamage.SetContainedAI(pCall_KhitomerTakingDamage)
	pHullTakingDamage.AddCondition(pHullAt99)
	pHullTakingDamage.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI HullTakingDamage
	#########################################
	#########################################
	# Creating PlainAI Call_KhitomerGoingToStation at (455, 205)
	pCall_KhitomerGoingToStation = App.PlainAI_Create(pShip, "Call_KhitomerGoingToStation")
	pCall_KhitomerGoingToStation.SetScriptModule("RunScript")
	pCall_KhitomerGoingToStation.SetInterruptable(1)
	pScript = pCall_KhitomerGoingToStation.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode6.E6M3.E6M3")
	pScript.SetFunction("KhitomerGoingToStation")
	# Done creating PlainAI Call_KhitomerGoingToStation
	#########################################
	#########################################
	# Creating CompoundAI E6M3_AI_Khit_Launch at (519, 253)
	import Maelstrom.Episode6.E6M3.E6M3_AI_Khit_Launch
	pE6M3_AI_Khit_Launch = Maelstrom.Episode6.E6M3.E6M3_AI_Khit_Launch.CreateAI(pShip)
	# Done creating CompoundAI E6M3_AI_Khit_Launch
	#########################################
	#########################################
	# Creating SequenceAI Sequence at (354, 306)
	pSequence = App.SequenceAI_Create(pShip, "Sequence")
	pSequence.SetInterruptable(1)
	pSequence.SetLoopCount(1)
	pSequence.SetResetIfInterrupted(1)
	pSequence.SetDoubleCheckAllDone(0)
	pSequence.SetSkipDormant(0)
	# SeqBlock is at (465, 265)
	pSequence.AddAI(pCall_KhitomerGoingToStation)
	pSequence.AddAI(pE6M3_AI_Khit_Launch)
	# Done creating SequenceAI Sequence
	#########################################
	#########################################
	# Creating ConditionalAI EnemiesInSet at (340, 364)
	## Conditions:
	#### Condition EnemyWithinSet
	pEnemyWithinSet = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 3000, pShip.GetName(), App.ObjectGroup_FromModule("Maelstrom.Episode6.E6M3.E6M3", "g_pSavoy3FedsTargets"))
	## Evaluation function:
	def EvalFunc(bEnemyWithinSet):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bEnemyWithinSet):
			return DORMANT
		return ACTIVE
	## The ConditionalAI:
	pEnemiesInSet = App.ConditionalAI_Create(pShip, "EnemiesInSet")
	pEnemiesInSet.SetInterruptable(1)
	pEnemiesInSet.SetContainedAI(pSequence)
	pEnemiesInSet.AddCondition(pEnemyWithinSet)
	pEnemiesInSet.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI EnemiesInSet
	#########################################
	#########################################
	# Creating CompoundAI AttackSavoy1FedsTargets at (489, 342)
	import AI.Compound.BasicAttack
	pAttackSavoy1FedsTargets = AI.Compound.BasicAttack.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode6.E6M3.E6M3", "g_pSavoy1FedsTargets"))
	# Done creating CompoundAI AttackSavoy1FedsTargets
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles_3 at (428, 394)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles_3 = App.PreprocessingAI_Create(pShip, "AvoidObstacles_3")
	pAvoidObstacles_3.SetInterruptable(1)
	pAvoidObstacles_3.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles_3.SetContainedAI(pAttackSavoy1FedsTargets)
	# Done creating PreprocessingAI AvoidObstacles_3
	#########################################
	#########################################
	# Creating PlainAI GotoStation at (620, 331)
	pGotoStation = App.PlainAI_Create(pShip, "GotoStation")
	pGotoStation.SetScriptModule("FollowWaypoints")
	pGotoStation.SetInterruptable(1)
	pScript = pGotoStation.GetScriptInstance()
	pScript.SetTargetWaypointName("KhitLaunch0")
	# Done creating PlainAI GotoStation
	#########################################
	#########################################
	# Creating PreprocessingAI Fire at (591, 376)
	## Setup:
	import AI.Preprocessors
	pFireScript = AI.Preprocessors.FireScript("Keldon 1")
	for pSystem in [ pShip.GetTorpedoSystem(), pShip.GetPhaserSystem(), pShip.GetPulseWeaponSystem() ]:
		if not App.IsNull(pSystem):
			pFireScript.AddWeaponSystem( pSystem )
	## The PreprocessingAI:
	pFire = App.PreprocessingAI_Create(pShip, "Fire")
	pFire.SetInterruptable(1)
	pFire.SetPreprocessingMethod(pFireScript, "Update")
	pFire.SetContainedAI(pGotoStation)
	# Done creating PreprocessingAI Fire
	#########################################
	#########################################
	# Creating PreprocessingAI SelectTarget at (541, 428)
	## Setup:
	import AI.Preprocessors
	pAllTargetsGroup = App.ObjectGroup()
	pAllTargetsGroup.AddName("Keldon 1")
	pAllTargetsGroup.AddName("Galor 3")
	pAllTargetsGroup.AddName("Galor 1")
	pAllTargetsGroup.AddName("Galor 2")
	pAllTargetsGroup.AddName("Keldon 2")
	pAllTargetsGroup.AddName("Transport 1")
	pAllTargetsGroup.AddName("Transport 2")
	pSelectionPreprocess = AI.Preprocessors.SelectTarget(pAllTargetsGroup)
	## The PreprocessingAI:
	pSelectTarget = App.PreprocessingAI_Create(pShip, "SelectTarget")
	pSelectTarget.SetInterruptable(1)
	pSelectTarget.SetPreprocessingMethod(pSelectionPreprocess, "Update")
	pSelectTarget.SetContainedAI(pFire)
	# Done creating PreprocessingAI SelectTarget
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles_2 at (457, 475)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles_2 = App.PreprocessingAI_Create(pShip, "AvoidObstacles_2")
	pAvoidObstacles_2.SetInterruptable(1)
	pAvoidObstacles_2.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles_2.SetContainedAI(pSelectTarget)
	# Done creating PreprocessingAI AvoidObstacles_2
	#########################################
	#########################################
	# Creating PriorityListAI Savoy1PriorityList at (219, 450)
	pSavoy1PriorityList = App.PriorityListAI_Create(pShip, "Savoy1PriorityList")
	pSavoy1PriorityList.SetInterruptable(1)
	# SeqBlock is at (355, 449)
	pSavoy1PriorityList.AddAI(pHullTakingDamage, 1)
	pSavoy1PriorityList.AddAI(pEnemiesInSet, 2)
	pSavoy1PriorityList.AddAI(pAvoidObstacles_3, 3)
	pSavoy1PriorityList.AddAI(pAvoidObstacles_2, 4)
	# Done creating PriorityListAI Savoy1PriorityList
	#########################################
	#########################################
	# Creating SequenceAI MainSequence at (8, 412)
	pMainSequence = App.SequenceAI_Create(pShip, "MainSequence")
	pMainSequence.SetInterruptable(1)
	pMainSequence.SetLoopCount(1)
	pMainSequence.SetResetIfInterrupted(1)
	pMainSequence.SetDoubleCheckAllDone(0)
	pMainSequence.SetSkipDormant(0)
	# SeqBlock is at (122, 364)
	pMainSequence.AddAI(pAvoidObstacles)
	pMainSequence.AddAI(pSavoy1PriorityList)
	# Done creating SequenceAI MainSequence
	#########################################
	return pMainSequence
