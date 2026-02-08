import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI StationaryAttackPlayer at (29, 51)
	pStationaryAttackPlayer = App.PlainAI_Create(pShip, "StationaryAttackPlayer")
	pStationaryAttackPlayer.SetScriptModule("StationaryAttack")
	pStationaryAttackPlayer.SetInterruptable(1)
	pScript = pStationaryAttackPlayer.GetScriptInstance()
	pScript.SetTargetObjectName("player")
	# Done creating PlainAI StationaryAttackPlayer
	#########################################
	#########################################
	# Creating ConditionalAI ShortTimer at (30, 104)
	## Conditions:
	#### Condition TimerA
	pTimerA = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 15)
	## Evaluation function:
	def EvalFunc(bTimerA):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bTimerA:
			return DONE
		return ACTIVE
	## The ConditionalAI:
	pShortTimer = App.ConditionalAI_Create(pShip, "ShortTimer")
	pShortTimer.SetInterruptable(1)
	pShortTimer.SetContainedAI(pStationaryAttackPlayer)
	pShortTimer.AddCondition(pTimerA)
	pShortTimer.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI ShortTimer
	#########################################
	#########################################
	# Creating PreprocessingAI AtPlayerFire at (30, 152)
	## Setup:
	import AI.Preprocessors
	pFireScript = AI.Preprocessors.FireScript("player")
	for pSystem in [ pShip.GetPhaserSystem(), pShip.GetPulseWeaponSystem() ]:
		if pSystem:
			pFireScript.AddWeaponSystem( pSystem )
	## The PreprocessingAI:
	pAtPlayerFire = App.PreprocessingAI_Create(pShip, "AtPlayerFire")
	pAtPlayerFire.SetInterruptable(1)
	pAtPlayerFire.SetPreprocessingMethod(pFireScript, "Update")
	pAtPlayerFire.SetContainedAI(pShortTimer)
	# Done creating PreprocessingAI AtPlayerFire
	#########################################
	#########################################
	# Creating PreprocessingAI DeCloak at (29, 199)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.CloakShip(0)
	## The PreprocessingAI:
	pDeCloak = App.PreprocessingAI_Create(pShip, "DeCloak")
	pDeCloak.SetInterruptable(1)
	pDeCloak.SetPreprocessingMethod(pScript, "Update")
	pDeCloak.SetContainedAI(pAtPlayerFire)
	# Done creating PreprocessingAI DeCloak
	#########################################
	#########################################
	# Creating PlainAI FlyWaypoints at (144, 51)
	pFlyWaypoints = App.PlainAI_Create(pShip, "FlyWaypoints")
	pFlyWaypoints.SetScriptModule("FollowWaypoints")
	pFlyWaypoints.SetInterruptable(1)
	pScript = pFlyWaypoints.GetScriptInstance()
	pScript.SetTargetWaypointName("WarbirdWay1")
	# Done creating PlainAI FlyWaypoints
	#########################################
	#########################################
	# Creating ConditionalAI Timer at (144, 104)
	## Conditions:
	#### Condition MediumTimer
	pMediumTimer = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 35)
	## Evaluation function:
	def EvalFunc(bMediumTimer):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bMediumTimer:
			return DONE
		return ACTIVE
	## The ConditionalAI:
	pTimer = App.ConditionalAI_Create(pShip, "Timer")
	pTimer.SetInterruptable(1)
	pTimer.SetContainedAI(pFlyWaypoints)
	pTimer.AddCondition(pMediumTimer)
	pTimer.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI Timer
	#########################################
	#########################################
	# Creating PreprocessingAI Cloak at (142, 155)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.CloakShip(1)
	## The PreprocessingAI:
	pCloak = App.PreprocessingAI_Create(pShip, "Cloak")
	pCloak.SetInterruptable(1)
	pCloak.SetPreprocessingMethod(pScript, "Update")
	pCloak.SetContainedAI(pTimer)
	# Done creating PreprocessingAI Cloak
	#########################################
	#########################################
	# Creating PlainAI TorpRun at (164, 198)
	pTorpRun = App.PlainAI_Create(pShip, "TorpRun")
	pTorpRun.SetScriptModule("TorpedoRun")
	pTorpRun.SetInterruptable(1)
	pScript = pTorpRun.GetScriptInstance()
	pScript.SetTargetObjectName("player")
	# Done creating PlainAI TorpRun
	#########################################
	#########################################
	# Creating ConditionalAI ReallyShortTimer at (167, 249)
	## Conditions:
	#### Condition TimerC
	pTimerC = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 1)
	## Evaluation function:
	def EvalFunc(bTimerC):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bTimerC:
			return DONE
		return ACTIVE
	## The ConditionalAI:
	pReallyShortTimer = App.ConditionalAI_Create(pShip, "ReallyShortTimer")
	pReallyShortTimer.SetInterruptable(1)
	pReallyShortTimer.SetContainedAI(pTorpRun)
	pReallyShortTimer.AddCondition(pTimerC)
	pReallyShortTimer.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI ReallyShortTimer
	#########################################
	#########################################
	# Creating SequenceAI StartAttackSequence at (10, 280)
	pStartAttackSequence = App.SequenceAI_Create(pShip, "StartAttackSequence")
	pStartAttackSequence.SetInterruptable(1)
	pStartAttackSequence.SetLoopCount(1)
	pStartAttackSequence.SetResetIfInterrupted(1)
	pStartAttackSequence.SetDoubleCheckAllDone(0)
	pStartAttackSequence.SetSkipDormant(0)
	# SeqBlock is at (106, 286)
	pStartAttackSequence.AddAI(pDeCloak)
	pStartAttackSequence.AddAI(pCloak)
	pStartAttackSequence.AddAI(pReallyShortTimer)
	# Done creating SequenceAI StartAttackSequence
	#########################################
	#########################################
	# Creating PlainAI InterceptKaroon at (360, 11)
	pInterceptKaroon = App.PlainAI_Create(pShip, "InterceptKaroon")
	pInterceptKaroon.SetScriptModule("Intercept")
	pInterceptKaroon.SetInterruptable(1)
	pScript = pInterceptKaroon.GetScriptInstance()
	pScript.SetTargetObjectName("Karoon")
	pScript.SetInterceptDistance(228)
	pScript.SetInSystemWarpDistance(1000)
	# Done creating PlainAI InterceptKaroon
	#########################################
	#########################################
	# Creating CompoundAI WarbirdAttackKaroon at (472, 8)
	import AI.Compound.BasicAttack
	pWarbirdAttackKaroon = AI.Compound.BasicAttack.CreateAI(pShip, "Karoon", Difficulty = 0.31, UseCloaking = 1)
	# Done creating CompoundAI WarbirdAttackKaroon
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList_2 at (284, 63)
	pPriorityList_2 = App.PriorityListAI_Create(pShip, "PriorityList_2")
	pPriorityList_2.SetInterruptable(1)
	# SeqBlock is at (415, 69)
	pPriorityList_2.AddAI(pInterceptKaroon, 1)
	pPriorityList_2.AddAI(pWarbirdAttackKaroon, 2)
	# Done creating PriorityListAI PriorityList_2
	#########################################
	#########################################
	# Creating ConditionalAI PlayerNotNearKaroon at (290, 113)
	## Conditions:
	#### Condition PlayerNearKaroon
	pPlayerNearKaroon = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 350, "player", "Karoon")
	## Evaluation function:
	def EvalFunc(bPlayerNearKaroon):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bPlayerNearKaroon:
			return DORMANT
		return ACTIVE
	## The ConditionalAI:
	pPlayerNotNearKaroon = App.ConditionalAI_Create(pShip, "PlayerNotNearKaroon")
	pPlayerNotNearKaroon.SetInterruptable(1)
	pPlayerNotNearKaroon.SetContainedAI(pPriorityList_2)
	pPlayerNotNearKaroon.AddCondition(pPlayerNearKaroon)
	pPlayerNotNearKaroon.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI PlayerNotNearKaroon
	#########################################
	#########################################
	# Creating CompoundAI WarbirdAttackPlayer at (335, 160)
	import AI.Compound.BasicAttack
	pWarbirdAttackPlayer = AI.Compound.BasicAttack.CreateAI(pShip, "player", Easy_Difficulty = 0.1, Easy_UseCloaking = 1, Difficulty = 0.2, UseCloaking = 1, Hard_Difficulty = 0.3, Hard_UseCloaking = 1)
	# Done creating CompoundAI WarbirdAttackPlayer
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (261, 259)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (288, 220)
	pPriorityList.AddAI(pPlayerNotNearKaroon, 1)
	pPriorityList.AddAI(pWarbirdAttackPlayer, 2)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating ConditionalAI TakenEnoughDamage at (198, 303)
	## Conditions:
	#### Condition CriticalSystemDamaged
	pCriticalSystemDamaged = App.ConditionScript_Create("Conditions.ConditionCriticalSystemBelow", "ConditionCriticalSystemBelow", pShip.GetName(), 0.70)
	#### Condition KaroonInBeol
	pKaroonInBeol = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", "Karoon", "Beol4")
	## Evaluation function:
	def EvalFunc(bCriticalSystemDamaged, bKaroonInBeol):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bCriticalSystemDamaged) or (not bKaroonInBeol):
			return DONE
		return ACTIVE
	## The ConditionalAI:
	pTakenEnoughDamage = App.ConditionalAI_Create(pShip, "TakenEnoughDamage")
	pTakenEnoughDamage.SetInterruptable(1)
	pTakenEnoughDamage.SetContainedAI(pPriorityList)
	pTakenEnoughDamage.AddCondition(pCriticalSystemDamaged)
	pTakenEnoughDamage.AddCondition(pKaroonInBeol)
	pTakenEnoughDamage.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI TakenEnoughDamage
	#########################################
	#########################################
	# Creating PlainAI FleeFromPlayer at (373, 218)
	pFleeFromPlayer = App.PlainAI_Create(pShip, "FleeFromPlayer")
	pFleeFromPlayer.SetScriptModule("Flee")
	pFleeFromPlayer.SetInterruptable(1)
	pScript = pFleeFromPlayer.GetScriptInstance()
	pScript.SetFleeFromGroup("player")
	pScript.SetSpeed(1)
	# Done creating PlainAI FleeFromPlayer
	#########################################
	#########################################
	# Creating PreprocessingAI Cloak_2 at (378, 275)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.CloakShip(1)
	## The PreprocessingAI:
	pCloak_2 = App.PreprocessingAI_Create(pShip, "Cloak_2")
	pCloak_2.SetInterruptable(1)
	pCloak_2.SetPreprocessingMethod(pScript, "Update")
	pCloak_2.SetContainedAI(pFleeFromPlayer)
	# Done creating PreprocessingAI Cloak_2
	#########################################
	#########################################
	# Creating ConditionalAI TimeBeforeWarp at (379, 314)
	## Conditions:
	#### Condition Timer
	pTimer = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 15, 0)
	## Evaluation function:
	def EvalFunc(bTimer):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bTimer:
			return DONE
		return ACTIVE
	## The ConditionalAI:
	pTimeBeforeWarp = App.ConditionalAI_Create(pShip, "TimeBeforeWarp")
	pTimeBeforeWarp.SetInterruptable(1)
	pTimeBeforeWarp.SetContainedAI(pCloak_2)
	pTimeBeforeWarp.AddCondition(pTimer)
	pTimeBeforeWarp.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI TimeBeforeWarp
	#########################################
	#########################################
	# Creating PlainAI WarpOutOfSet at (284, 360)
	pWarpOutOfSet = App.PlainAI_Create(pShip, "WarpOutOfSet")
	pWarpOutOfSet.SetScriptModule("Warp")
	pWarpOutOfSet.SetInterruptable(1)
	pScript = pWarpOutOfSet.GetScriptInstance()
	pScript.WarpBlindlyNoCollisionsIfImpulseDisabled(bWarpBlindly = 1)
	# Done creating PlainAI WarpOutOfSet
	#########################################
	#########################################
	# Creating SequenceAI MainSequence at (15, 354)
	pMainSequence = App.SequenceAI_Create(pShip, "MainSequence")
	pMainSequence.SetInterruptable(1)
	pMainSequence.SetLoopCount(1)
	pMainSequence.SetResetIfInterrupted(1)
	pMainSequence.SetDoubleCheckAllDone(0)
	pMainSequence.SetSkipDormant(0)
	# SeqBlock is at (116, 364)
	pMainSequence.AddAI(pStartAttackSequence)
	pMainSequence.AddAI(pTakenEnoughDamage)
	pMainSequence.AddAI(pTimeBeforeWarp)
	pMainSequence.AddAI(pWarpOutOfSet)
	# Done creating SequenceAI MainSequence
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (15, 409)
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
