import App

def CreateAI(pShip, pTargetGroup, pPlayerInHelpCondition, sPlacementName):


	#########################################
	# Creating PlainAI FaceSovereign at (10, 131)
	pFaceSovereign = App.PlainAI_Create(pShip, "FaceSovereign")
	pFaceSovereign.SetScriptModule("TurnToOrientation")
	pFaceSovereign.SetInterruptable(1)
	pScript = pFaceSovereign.GetScriptInstance()
	pScript.SetObjectName("Sovereign")
	pScript.SetPrimaryDirection(vDirection = App.TGPoint3_GetModelForward())
	# Done creating PlainAI FaceSovereign
	#########################################
	#########################################
	# Creating PreprocessingAI FireOnSovereign at (9, 191)
	## Setup:
	import AI.Preprocessors
	pFireScript = AI.Preprocessors.FireScript("Sovereign")
	for pSystem in [ pShip.GetPhaserSystem(), pShip.GetPulseWeaponSystem() ]:
		if pSystem:
			pFireScript.AddWeaponSystem( pSystem )
	## The PreprocessingAI:
	pFireOnSovereign = App.PreprocessingAI_Create(pShip, "FireOnSovereign")
	pFireOnSovereign.SetInterruptable(1)
	pFireOnSovereign.SetPreprocessingMethod(pFireScript, "Update")
	pFireOnSovereign.SetContainedAI(pFaceSovereign)
	# Done creating PreprocessingAI FireOnSovereign
	#########################################
	#########################################
	# Creating ConditionalAI ShortTimer at (11, 239)
	## Conditions:
	#### Condition TimerA
	pTimerA = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 5)
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
	pShortTimer.SetContainedAI(pFireOnSovereign)
	pShortTimer.AddCondition(pTimerA)
	pShortTimer.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI ShortTimer
	#########################################
	#########################################
	# Creating PlainAI FlyToWaypoint at (104, 76)
	pFlyToWaypoint = App.PlainAI_Create(pShip, "FlyToWaypoint")
	pFlyToWaypoint.SetScriptModule("FollowWaypoints")
	pFlyToWaypoint.SetInterruptable(1)
	pScript = pFlyToWaypoint.GetScriptInstance()
	pScript.SetTargetWaypointName(sPlacementName)
	# Done creating PlainAI FlyToWaypoint
	#########################################
	#########################################
	# Creating ConditionalAI LongerTimer at (105, 126)
	## Conditions:
	#### Condition TimerB
	pTimerB = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 30)
	## Evaluation function:
	def EvalFunc(bTimerB):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bTimerB:
			return DONE
		return ACTIVE
	## The ConditionalAI:
	pLongerTimer = App.ConditionalAI_Create(pShip, "LongerTimer")
	pLongerTimer.SetInterruptable(1)
	pLongerTimer.SetContainedAI(pFlyToWaypoint)
	pLongerTimer.AddCondition(pTimerB)
	pLongerTimer.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI LongerTimer
	#########################################
	#########################################
	# Creating PreprocessingAI Cloak at (107, 176)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.CloakShip(1)
	## The PreprocessingAI:
	pCloak = App.PreprocessingAI_Create(pShip, "Cloak")
	pCloak.SetInterruptable(1)
	pCloak.SetPreprocessingMethod(pScript, "Update")
	pCloak.SetContainedAI(pLongerTimer)
	# Done creating PreprocessingAI Cloak
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles_2 at (106, 224)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles_2 = App.PreprocessingAI_Create(pShip, "AvoidObstacles_2")
	pAvoidObstacles_2.SetInterruptable(1)
	pAvoidObstacles_2.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles_2.SetContainedAI(pCloak)
	# Done creating PreprocessingAI AvoidObstacles_2
	#########################################
	#########################################
	# Creating PlainAI Call_WarbirdsWarpOut at (227, 162)
	pCall_WarbirdsWarpOut = App.PlainAI_Create(pShip, "Call_WarbirdsWarpOut")
	pCall_WarbirdsWarpOut.SetScriptModule("RunScript")
	pCall_WarbirdsWarpOut.SetInterruptable(1)
	pScript = pCall_WarbirdsWarpOut.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode2.E2M0.E2M0")
	pScript.SetFunction("WarbirdsWarpOut")
	# Done creating PlainAI Call_WarbirdsWarpOut
	#########################################
	#########################################
	# Creating ConditionalAI TakingCriticalDamage at (240, 219)
	## Conditions:
	#### Condition CriticalDamageWarbird1
	pCriticalDamageWarbird1 = App.ConditionScript_Create("Conditions.ConditionCriticalSystemBelow", "ConditionCriticalSystemBelow", "Warbird 1", 0.60)
	#### Condition CriticalDamageWarbird2
	pCriticalDamageWarbird2 = App.ConditionScript_Create("Conditions.ConditionCriticalSystemBelow", "ConditionCriticalSystemBelow", "Warbird 2", 0.60)
	## Evaluation function:
	def EvalFunc(bCriticalDamageWarbird1, bCriticalDamageWarbird2):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bCriticalDamageWarbird1 or bCriticalDamageWarbird2:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pTakingCriticalDamage = App.ConditionalAI_Create(pShip, "TakingCriticalDamage")
	pTakingCriticalDamage.SetInterruptable(1)
	pTakingCriticalDamage.SetContainedAI(pCall_WarbirdsWarpOut)
	pTakingCriticalDamage.AddCondition(pCriticalDamageWarbird1)
	pTakingCriticalDamage.AddCondition(pCriticalDamageWarbird2)
	pTakingCriticalDamage.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI TakingCriticalDamage
	#########################################
	#########################################
	# Creating CompoundAI AttackTargetsNoCloak at (331, 158)
	import AI.Compound.BasicAttack
	pAttackTargetsNoCloak = AI.Compound.BasicAttack.CreateAI(pShip, "RanKuf", "Trayor", Difficulty = 0.31, MaxFiringRange = 358.0, AvoidTorps = 1, ChooseSubsystemTargets = 1, DisableOnly = 1, SmartShields = 1, UseCloaking = 0)
	# Done creating CompoundAI AttackTargetsNoCloak
	#########################################
	#########################################
	# Creating ConditionalAI PlayerInHelp at (330, 213)
	## Evaluation function:
	def EvalFunc():
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		# THIS EVAL FUNCTION ISN'T USED.  It's being done with special
		# code below this AI in the text file.
		return ACTIVE
	## The ConditionalAI:
	pPlayerInHelp = App.ConditionalAI_Create(pShip, "PlayerInHelp")
	pPlayerInHelp.SetInterruptable(1)
	pPlayerInHelp.SetContainedAI(pAttackTargetsNoCloak)
	pPlayerInHelp.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI PlayerInHelp
	#########################################
	pPlayerInHelp.AddCondition( pPlayerInHelpCondition )
	def EvalFunc(bInHelp):
		if bInHelp:
			return App.ArtificialIntelligence.US_ACTIVE
		return App.ArtificialIntelligence.US_DORMANT
	pPlayerInHelp.SetEvaluationFunction( EvalFunc )

	#########################################
	# Creating CompoundAI AttackSovereign at (443, 104)
	import AI.Compound.BasicAttack
	pAttackSovereign = AI.Compound.BasicAttack.CreateAI(pShip, "Sovereign", Difficulty = 0.32, MaxFiringRange = 411.0, AggressivePulseWeapons = 1, ChooseSubsystemTargets = 1, DisableBeforeDestroy = 1, SmartShields = 1, UseCloaking = 1)
	# Done creating CompoundAI AttackSovereign
	#########################################
	#########################################
	# Creating ConditionalAI PlayerHasntAttacked at (445, 160)
	## Conditions:
	#### Condition PlayerAttackedWarbird1
	pPlayerAttackedWarbird1 = App.ConditionScript_Create("Conditions.ConditionAttackedBy", "ConditionAttackedBy", "Warbird 1", "player", 0.05, 0.05, 20, 120)
	#### Condition PlayerAttackedWarbird2
	pPlayerAttackedWarbird2 = App.ConditionScript_Create("Conditions.ConditionAttackedBy", "ConditionAttackedBy", "Warbird 2", "player", 0.05, 0.05, 20, 120)
	## Evaluation function:
	def EvalFunc(bPlayerAttackedWarbird1, bPlayerAttackedWarbird2):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bPlayerAttackedWarbird1 or bPlayerAttackedWarbird2:
			return DORMANT
		return ACTIVE
	## The ConditionalAI:
	pPlayerHasntAttacked = App.ConditionalAI_Create(pShip, "PlayerHasntAttacked")
	pPlayerHasntAttacked.SetInterruptable(1)
	pPlayerHasntAttacked.SetContainedAI(pAttackSovereign)
	pPlayerHasntAttacked.AddCondition(pPlayerAttackedWarbird1)
	pPlayerHasntAttacked.AddCondition(pPlayerAttackedWarbird2)
	pPlayerHasntAttacked.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI PlayerHasntAttacked
	#########################################
	#########################################
	# Creating ConditionalAI GraceTimer at (442, 215)
	## Conditions:
	#### Condition TimerGrace
	pTimerGrace = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 180, 0)
	## Evaluation function:
	def EvalFunc(bTimerGrace):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bTimerGrace:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pGraceTimer = App.ConditionalAI_Create(pShip, "GraceTimer")
	pGraceTimer.SetInterruptable(1)
	pGraceTimer.SetContainedAI(pPlayerHasntAttacked)
	pGraceTimer.AddCondition(pTimerGrace)
	pGraceTimer.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI GraceTimer
	#########################################
	#########################################
	# Creating CompoundAI AttackTargets at (427, 269)
	import AI.Compound.BasicAttack
	pAttackTargets = AI.Compound.BasicAttack.CreateAI(pShip, pTargetGroup, Difficulty = 0.31, MaxFiringRange = 358.0, DisableBeforeDestroy = 1, SmartShields = 1, UseCloaking = 1)
	# Done creating CompoundAI AttackTargets
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (191, 261)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (310, 277)
	pPriorityList.AddAI(pTakingCriticalDamage, 1)
	pPriorityList.AddAI(pPlayerInHelp, 2)
	pPriorityList.AddAI(pGraceTimer, 3)
	pPriorityList.AddAI(pAttackTargets, 4)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles_3 at (193, 311)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles_3 = App.PreprocessingAI_Create(pShip, "AvoidObstacles_3")
	pAvoidObstacles_3.SetInterruptable(1)
	pAvoidObstacles_3.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles_3.SetContainedAI(pPriorityList)
	# Done creating PreprocessingAI AvoidObstacles_3
	#########################################
	#########################################
	# Creating SequenceAI MainSequence at (5, 310)
	pMainSequence = App.SequenceAI_Create(pShip, "MainSequence")
	pMainSequence.SetInterruptable(1)
	pMainSequence.SetLoopCount(1)
	pMainSequence.SetResetIfInterrupted(1)
	pMainSequence.SetDoubleCheckAllDone(0)
	pMainSequence.SetSkipDormant(0)
	# SeqBlock is at (123, 317)
	pMainSequence.AddAI(pShortTimer)
	pMainSequence.AddAI(pAvoidObstacles_2)
	pMainSequence.AddAI(pAvoidObstacles_3)
	# Done creating SequenceAI MainSequence
	#########################################
	return pMainSequence
