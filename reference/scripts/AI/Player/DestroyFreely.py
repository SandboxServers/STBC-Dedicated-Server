import App
def CreateAI(pShip, pTarget):
	if pTarget:
		sTarget = pTarget.GetName()
		fTargetRadius = pTarget.GetRadius()
	else:
		sTarget = ""
		fTargetRadius = 0.0

	# Not useful to try to attack if we're farther than this distance.
	fMaxWeaponDist = 15.0 / 0.175		# 15 km base

	# add our ship and target ship's radius so that it's 15km from
	# surface to surface (approximately).  This will keep us from running
	# into big ships when we're attacking.
	fMaxWeaponDist = fMaxWeaponDist + pShip.GetRadius() + fTargetRadius



	#########################################
	# Creating PlainAI TorpRun_3 at (29, 26)
	pTorpRun_3 = App.PlainAI_Create(pShip, "TorpRun_3")
	pTorpRun_3.SetScriptModule("TorpedoRun")
	pTorpRun_3.SetInterruptable(1)
	pScript = pTorpRun_3.GetScriptInstance()
	pScript.SetTargetObjectName(sTarget)
	pScript.SetPerpendicularMovementAdjustment(0.25)
	# Done creating PlainAI TorpRun_3
	#########################################
	#########################################
	# Creating PreprocessingAI AttackStatus_LiningUpFront at (31, 81)
	## Setup:
	import AI.Preprocessors
	pPreprocess = AI.Preprocessors.UpdateAIStatus("AttackStatus_LiningUpFront")
	## The PreprocessingAI:
	pAttackStatus_LiningUpFront = App.PreprocessingAI_Create(pShip, "AttackStatus_LiningUpFront")
	pAttackStatus_LiningUpFront.SetInterruptable(1)
	pAttackStatus_LiningUpFront.SetPreprocessingMethod(pPreprocess, "Update")
	pAttackStatus_LiningUpFront.SetContainedAI(pTorpRun_3)
	# Done creating PreprocessingAI AttackStatus_LiningUpFront
	#########################################
	#########################################
	# Creating ConditionalAI TorpsReady at (34, 132)
	## Conditions:
	#### Condition Ready
	pReady = App.ConditionScript_Create("Conditions.ConditionTorpsReady", "ConditionTorpsReady", pShip.GetName(), App.TGPoint3_GetModelForward())
	#### Condition UsingTorps
	pUsingTorps = App.ConditionScript_Create("Conditions.ConditionUsingWeapon", "ConditionUsingWeapon", App.CT_TORPEDO_SYSTEM)
	## Evaluation function:
	def EvalFunc(bReady, bUsingTorps):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bReady and bUsingTorps:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pTorpsReady = App.ConditionalAI_Create(pShip, "TorpsReady")
	pTorpsReady.SetInterruptable(1)
	pTorpsReady.SetContainedAI(pAttackStatus_LiningUpFront)
	pTorpsReady.AddCondition(pReady)
	pTorpsReady.AddCondition(pUsingTorps)
	pTorpsReady.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI TorpsReady
	#########################################
	#########################################
	# Creating PlainAI SweepPhasers at (145, 81)
	pSweepPhasers = App.PlainAI_Create(pShip, "SweepPhasers")
	pSweepPhasers.SetScriptModule("PhaserSweep")
	pSweepPhasers.SetInterruptable(1)
	pScript = pSweepPhasers.GetScriptInstance()
	pScript.SetTargetObjectName(sTarget)
	pScript.SetSweepPhasersDuringRun(130.0)
	pScript.SetSpeedFraction(0.4)
	pScript.SetPrimaryDirection(App.TGPoint3_GetModelForward())
	# Done creating PlainAI SweepPhasers
	#########################################
	#########################################
	# Creating PreprocessingAI AttackStatus_SweepingPhasers at (136, 138)
	## Setup:
	import AI.Preprocessors
	pPreprocess = AI.Preprocessors.UpdateAIStatus("AttackStatus_SweepingPhasers")
	## The PreprocessingAI:
	pAttackStatus_SweepingPhasers = App.PreprocessingAI_Create(pShip, "AttackStatus_SweepingPhasers")
	pAttackStatus_SweepingPhasers.SetInterruptable(1)
	pAttackStatus_SweepingPhasers.SetPreprocessingMethod(pPreprocess, "Update")
	pAttackStatus_SweepingPhasers.SetContainedAI(pSweepPhasers)
	# Done creating PreprocessingAI AttackStatus_SweepingPhasers
	#########################################
	#########################################
	# Creating PriorityListAI TooFarPriorities at (17, 200)
	pTooFarPriorities = App.PriorityListAI_Create(pShip, "TooFarPriorities")
	pTooFarPriorities.SetInterruptable(1)
	# SeqBlock is at (146, 205)
	pTooFarPriorities.AddAI(pTorpsReady, 1)
	pTooFarPriorities.AddAI(pAttackStatus_SweepingPhasers, 2)
	# Done creating PriorityListAI TooFarPriorities
	#########################################
	#########################################
	# Creating ConditionalAI TooFar at (81, 253)
	## Conditions:
	#### Condition InRange
	pInRange = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 50.0 + fTargetRadius, sTarget, pShip.GetName())
	## Evaluation function:
	def EvalFunc(bInRange):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bInRange:
			return DONE
		return ACTIVE
	## The ConditionalAI:
	pTooFar = App.ConditionalAI_Create(pShip, "TooFar")
	pTooFar.SetInterruptable(1)
	pTooFar.SetContainedAI(pTooFarPriorities)
	pTooFar.AddCondition(pInRange)
	pTooFar.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI TooFar
	#########################################
	#########################################
	# Creating PlainAI RearTorpRun at (387, 22)
	pRearTorpRun = App.PlainAI_Create(pShip, "RearTorpRun")
	pRearTorpRun.SetScriptModule("TorpedoRun")
	pRearTorpRun.SetInterruptable(1)
	pScript = pRearTorpRun.GetScriptInstance()
	pScript.SetTargetObjectName(sTarget)
	pScript.SetPerpendicularMovementAdjustment(0.3)
	pScript.SetTorpDirection(App.TGPoint3_GetModelBackward())
	# Done creating PlainAI RearTorpRun
	#########################################
	#########################################
	# Creating PreprocessingAI AttackStatus_RearTorpRun at (393, 78)
	## Setup:
	import AI.Preprocessors
	pPreprocess = AI.Preprocessors.UpdateAIStatus("AttackStatus_RearTorpRun")
	## The PreprocessingAI:
	pAttackStatus_RearTorpRun = App.PreprocessingAI_Create(pShip, "AttackStatus_RearTorpRun")
	pAttackStatus_RearTorpRun.SetInterruptable(1)
	pAttackStatus_RearTorpRun.SetPreprocessingMethod(pPreprocess, "Update")
	pAttackStatus_RearTorpRun.SetContainedAI(pRearTorpRun)
	# Done creating PreprocessingAI AttackStatus_RearTorpRun
	#########################################
	#########################################
	# Creating ConditionalAI RearTorpsReady at (396, 132)
	## Conditions:
	#### Condition TorpsReady
	pTorpsReady = App.ConditionScript_Create("Conditions.ConditionTorpsReady", "ConditionTorpsReady", pShip.GetName(), App.TGPoint3_GetModelBackward())
	#### Condition UsingTorps
	pUsingTorps = App.ConditionScript_Create("Conditions.ConditionUsingWeapon", "ConditionUsingWeapon", App.CT_TORPEDO_SYSTEM)
	## Evaluation function:
	def EvalFunc(bTorpsReady, bUsingTorps):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bTorpsReady and bUsingTorps:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pRearTorpsReady = App.ConditionalAI_Create(pShip, "RearTorpsReady")
	pRearTorpsReady.SetInterruptable(1)
	pRearTorpsReady.SetContainedAI(pAttackStatus_RearTorpRun)
	pRearTorpsReady.AddCondition(pTorpsReady)
	pRearTorpsReady.AddCondition(pUsingTorps)
	pRearTorpsReady.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI RearTorpsReady
	#########################################
	#########################################
	# Creating PlainAI ICO_Flee at (509, 91)
	pICO_Flee = App.PlainAI_Create(pShip, "ICO_Flee")
	pICO_Flee.SetScriptModule("IntelligentCircleObject")
	pICO_Flee.SetInterruptable(1)
	pScript = pICO_Flee.GetScriptInstance()
	pScript.SetFollowObjectName(sTarget)
	pScript.SetForwardBias(-0.5)
	# Done creating PlainAI ICO_Flee
	#########################################
	#########################################
	# Creating ConditionalAI RearShieldLow at (508, 141)
	## Conditions:
	#### Condition ShieldLow
	pShieldLow = App.ConditionScript_Create("Conditions.ConditionSingleShieldBelow", "ConditionSingleShieldBelow", pShip.GetName(), 0.6, App.ShieldClass.REAR_SHIELDS)
	## Evaluation function:
	def EvalFunc(bShieldLow):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bShieldLow:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pRearShieldLow = App.ConditionalAI_Create(pShip, "RearShieldLow")
	pRearShieldLow.SetInterruptable(1)
	pRearShieldLow.SetContainedAI(pICO_Flee)
	pRearShieldLow.AddCondition(pShieldLow)
	pRearShieldLow.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI RearShieldLow
	#########################################
	#########################################
	# Creating PlainAI SweepPhasers_2 at (572, 189)
	pSweepPhasers_2 = App.PlainAI_Create(pShip, "SweepPhasers_2")
	pSweepPhasers_2.SetScriptModule("PhaserSweep")
	pSweepPhasers_2.SetInterruptable(1)
	pScript = pSweepPhasers_2.GetScriptInstance()
	pScript.SetTargetObjectName(sTarget)
	pScript.SetSweepPhasersDuringRun(80.0)
	pScript.SetPrimaryDirection(App.TGPoint3_GetModelBackward())
	# Done creating PlainAI SweepPhasers_2
	#########################################
	#########################################
	# Creating PriorityListAI TooClosePriorities at (348, 196)
	pTooClosePriorities = App.PriorityListAI_Create(pShip, "TooClosePriorities")
	pTooClosePriorities.SetInterruptable(1)
	# SeqBlock is at (468, 203)
	pTooClosePriorities.AddAI(pRearTorpsReady, 1)
	pTooClosePriorities.AddAI(pRearShieldLow, 2)
	pTooClosePriorities.AddAI(pSweepPhasers_2, 3)
	# Done creating PriorityListAI TooClosePriorities
	#########################################
	#########################################
	# Creating PreprocessingAI AttackStatus_FallingBack at (258, 194)
	## Setup:
	import AI.Preprocessors
	pPreprocess = AI.Preprocessors.UpdateAIStatus("AttackStatus_FallingBack")
	## The PreprocessingAI:
	pAttackStatus_FallingBack = App.PreprocessingAI_Create(pShip, "AttackStatus_FallingBack")
	pAttackStatus_FallingBack.SetInterruptable(1)
	pAttackStatus_FallingBack.SetPreprocessingMethod(pPreprocess, "Update")
	pAttackStatus_FallingBack.SetContainedAI(pTooClosePriorities)
	# Done creating PreprocessingAI AttackStatus_FallingBack
	#########################################
	#########################################
	# Creating ConditionalAI TooClose at (265, 259)
	## Conditions:
	#### Condition InRange
	pInRange = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 70.0 + fTargetRadius, sTarget, pShip.GetName())
	## Evaluation function:
	def EvalFunc(bInRange):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bInRange:
			return ACTIVE
		return DONE
	## The ConditionalAI:
	pTooClose = App.ConditionalAI_Create(pShip, "TooClose")
	pTooClose.SetInterruptable(1)
	pTooClose.SetContainedAI(pAttackStatus_FallingBack)
	pTooClose.AddCondition(pInRange)
	pTooClose.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI TooClose
	#########################################
	#########################################
	# Creating SequenceAI Sequence at (190, 304)
	pSequence = App.SequenceAI_Create(pShip, "Sequence")
	pSequence.SetInterruptable(1)
	pSequence.SetLoopCount(-1)
	pSequence.SetResetIfInterrupted(1)
	pSequence.SetDoubleCheckAllDone(0)
	pSequence.SetSkipDormant(0)
	# SeqBlock is at (214, 276)
	pSequence.AddAI(pTooFar)
	pSequence.AddAI(pTooClose)
	# Done creating SequenceAI Sequence
	#########################################
	#########################################
	# Creating ConditionalAI InRange at (196, 359)
	## Conditions:
	#### Condition Close
	pClose = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", fMaxWeaponDist, pShip.GetName(), sTarget)
	## Evaluation function:
	def EvalFunc(bClose):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bClose:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pInRange = App.ConditionalAI_Create(pShip, "InRange")
	pInRange.SetInterruptable(1)
	pInRange.SetContainedAI(pSequence)
	pInRange.AddCondition(pClose)
	pInRange.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI InRange
	#########################################
	#########################################
	# Creating PlainAI Intercept at (413, 258)
	pIntercept = App.PlainAI_Create(pShip, "Intercept")
	pIntercept.SetScriptModule("Intercept")
	pIntercept.SetInterruptable(1)
	pScript = pIntercept.GetScriptInstance()
	pScript.SetTargetObjectName(sTarget)
	# Done creating PlainAI Intercept
	#########################################
	#########################################
	# Creating ConditionalAI VeryFar at (419, 309)
	## Conditions:
	#### Condition InRangeCond
	pInRangeCond = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 50.0 / 0.175, pShip.GetName(), sTarget)
	## Evaluation function:
	def EvalFunc(bInRangeCond):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bInRangeCond:
			return DORMANT
		return ACTIVE
	## The ConditionalAI:
	pVeryFar = App.ConditionalAI_Create(pShip, "VeryFar")
	pVeryFar.SetInterruptable(1)
	pVeryFar.SetContainedAI(pIntercept)
	pVeryFar.AddCondition(pInRangeCond)
	pVeryFar.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI VeryFar
	#########################################
	#########################################
	# Creating PlainAI MoveIn at (526, 290)
	pMoveIn = App.PlainAI_Create(pShip, "MoveIn")
	pMoveIn.SetScriptModule("FollowObject")
	pMoveIn.SetInterruptable(1)
	pScript = pMoveIn.GetScriptInstance()
	pScript.SetFollowObjectName(sTarget)
	# Done creating PlainAI MoveIn
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList_2 at (342, 366)
	pPriorityList_2 = App.PriorityListAI_Create(pShip, "PriorityList_2")
	pPriorityList_2.SetInterruptable(1)
	# SeqBlock is at (486, 375)
	pPriorityList_2.AddAI(pVeryFar, 1)
	pPriorityList_2.AddAI(pMoveIn, 2)
	# Done creating PriorityListAI PriorityList_2
	#########################################
	#########################################
	# Creating PreprocessingAI AttackStatus_MovingIn at (342, 417)
	## Setup:
	import AI.Preprocessors
	pPreprocess = AI.Preprocessors.UpdateAIStatus("AttackStatus_MovingIn")
	## The PreprocessingAI:
	pAttackStatus_MovingIn = App.PreprocessingAI_Create(pShip, "AttackStatus_MovingIn")
	pAttackStatus_MovingIn.SetInterruptable(1)
	pAttackStatus_MovingIn.SetPreprocessingMethod(pPreprocess, "Update")
	pAttackStatus_MovingIn.SetContainedAI(pPriorityList_2)
	# Done creating PreprocessingAI AttackStatus_MovingIn
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (114, 405)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (269, 425)
	pPriorityList.AddAI(pInRange, 1)
	pPriorityList.AddAI(pAttackStatus_MovingIn, 2)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (78, 307)
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
	# Creating PreprocessingAI FireAll at (17, 353)
	## Setup:
	import AI.Preprocessors
	pFireScript = AI.Preprocessors.FireScript(sTarget, MaxFiringRange = (40.0 / 0.175))
	for pSystem in [ pShip.GetTorpedoSystem(), pShip.GetPhaserSystem(), pShip.GetPulseWeaponSystem() ]:
		if not App.IsNull(pSystem):
			pFireScript.AddWeaponSystem( pSystem )
	## The PreprocessingAI:
	pFireAll = App.PreprocessingAI_Create(pShip, "FireAll")
	pFireAll.SetInterruptable(1)
	pFireAll.SetPreprocessingMethod(pFireScript, "Update")
	pFireAll.SetContainedAI(pAvoidObstacles)
	# Done creating PreprocessingAI FireAll
	#########################################
	#########################################
	# Creating PreprocessingAI SelectTarget at (17, 411)
	## Setup:
	import AI.Preprocessors
	import MissionLib
	pEnemies = MissionLib.GetMission().GetEnemyGroup()
	pSelectionPreprocess = AI.Preprocessors.SelectTarget(pEnemies)
	if sTarget:
		pSelectionPreprocess.ForceCurrentTargetString(sTarget)
	pSelectionPreprocess.UsePlayerSettings()
	## The PreprocessingAI:
	pSelectTarget = App.PreprocessingAI_Create(pShip, "SelectTarget")
	pSelectTarget.SetInterruptable(1)
	pSelectTarget.SetPreprocessingMethod(pSelectionPreprocess, "Update")
	pSelectTarget.SetContainedAI(pFireAll)
	# Done creating PreprocessingAI SelectTarget
	#########################################
	#########################################
	# Creating PreprocessingAI FelixReport at (13, 467)
	## Setup:
	import AI.Preprocessors
	pPreprocess = AI.Preprocessors.FelixReportStatus()
	## The PreprocessingAI:
	pFelixReport = App.PreprocessingAI_Create(pShip, "FelixReport")
	pFelixReport.SetInterruptable(1)
	pFelixReport.SetPreprocessingMethod(pPreprocess, "Update")
	pFelixReport.SetContainedAI(pSelectTarget)
	# Done creating PreprocessingAI FelixReport
	#########################################
	return pFelixReport
