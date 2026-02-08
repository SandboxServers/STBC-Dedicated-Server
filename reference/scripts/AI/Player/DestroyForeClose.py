import App

def CreateAI(pShip, pTarget):
	if pTarget:
		sTarget = pTarget.GetName()
		fTargetRadius = pTarget.GetRadius()
	else:
		sTarget = ""
		fTargetRadius = 0.0

	#########################################
	# Creating PlainAI Intercept at (170, 60)
	pIntercept = App.PlainAI_Create(pShip, "Intercept")
	pIntercept.SetScriptModule("Intercept")
	pIntercept.SetInterruptable(1)
	pScript = pIntercept.GetScriptInstance()
	pScript.SetTargetObjectName(sTarget)
	# Done creating PlainAI Intercept
	#########################################
	#########################################
	# Creating PreprocessingAI AttackStatus_MovingIn at (174, 106)
	## Setup:
	import AI.Preprocessors
	pPreprocess = AI.Preprocessors.UpdateAIStatus("AttackStatus_MovingIn")
	## The PreprocessingAI:
	pAttackStatus_MovingIn = App.PreprocessingAI_Create(pShip, "AttackStatus_MovingIn")
	pAttackStatus_MovingIn.SetInterruptable(1)
	pAttackStatus_MovingIn.SetPreprocessingMethod(pPreprocess, "Update")
	pAttackStatus_MovingIn.SetContainedAI(pIntercept)
	# Done creating PreprocessingAI AttackStatus_MovingIn
	#########################################
	#########################################
	# Creating ConditionalAI TooFar at (170, 166)
	## Conditions:
	#### Condition InRange
	pInRange = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 50.0 / 0.175, pShip.GetName(), sTarget)
	## Evaluation function:
	def EvalFunc(bInRange):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bInRange:
			return DORMANT
		return ACTIVE
	## The ConditionalAI:
	pTooFar = App.ConditionalAI_Create(pShip, "TooFar")
	pTooFar.SetInterruptable(1)
	pTooFar.SetContainedAI(pAttackStatus_MovingIn)
	pTooFar.AddCondition(pInRange)
	pTooFar.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI TooFar
	#########################################
	#########################################
	# Creating PlainAI StationaryAttack at (272, 14)
	pStationaryAttack = App.PlainAI_Create(pShip, "StationaryAttack")
	pStationaryAttack.SetScriptModule("StationaryAttack")
	pStationaryAttack.SetInterruptable(1)
	pScript = pStationaryAttack.GetScriptInstance()
	pScript.SetTargetObjectName(sTarget)
	# Done creating PlainAI StationaryAttack
	#########################################
	#########################################
	# Creating PreprocessingAI AttackStatus_LiningUpFront at (275, 62)
	## Setup:
	import AI.Preprocessors
	pPreprocess = AI.Preprocessors.UpdateAIStatus("AttackStatus_LiningUpFront")
	## The PreprocessingAI:
	pAttackStatus_LiningUpFront = App.PreprocessingAI_Create(pShip, "AttackStatus_LiningUpFront")
	pAttackStatus_LiningUpFront.SetInterruptable(1)
	pAttackStatus_LiningUpFront.SetPreprocessingMethod(pPreprocess, "Update")
	pAttackStatus_LiningUpFront.SetContainedAI(pStationaryAttack)
	# Done creating PreprocessingAI AttackStatus_LiningUpFront
	#########################################
	#########################################
	# Creating ConditionalAI ForwardTorpsReady at (275, 110)
	## Conditions:
	#### Condition TorpsReady
	pTorpsReady = App.ConditionScript_Create("Conditions.ConditionTorpsReady", "ConditionTorpsReady", pShip.GetName(), App.TGPoint3_GetModelForward())
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
	pForwardTorpsReady = App.ConditionalAI_Create(pShip, "ForwardTorpsReady")
	pForwardTorpsReady.SetInterruptable(1)
	pForwardTorpsReady.SetContainedAI(pAttackStatus_LiningUpFront)
	pForwardTorpsReady.AddCondition(pTorpsReady)
	pForwardTorpsReady.AddCondition(pUsingTorps)
	pForwardTorpsReady.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI ForwardTorpsReady
	#########################################
	#########################################
	# Creating PlainAI StoppedPhaserSweep at (367, 109)
	pStoppedPhaserSweep = App.PlainAI_Create(pShip, "StoppedPhaserSweep")
	pStoppedPhaserSweep.SetScriptModule("PhaserSweep")
	pStoppedPhaserSweep.SetInterruptable(1)
	pScript = pStoppedPhaserSweep.GetScriptInstance()
	pScript.SetTargetObjectName(sTarget)
	pScript.SetSweepPhasersDuringRun(65.0)
	pScript.SetSpeedFraction(0.0)
	pScript.SetPrimaryDirection(App.TGPoint3_GetModelForward())
	# Done creating PlainAI StoppedPhaserSweep
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList_3 at (282, 169)
	pPriorityList_3 = App.PriorityListAI_Create(pShip, "PriorityList_3")
	pPriorityList_3.SetInterruptable(1)
	# SeqBlock is at (387, 165)
	pPriorityList_3.AddAI(pForwardTorpsReady, 1)
	pPriorityList_3.AddAI(pStoppedPhaserSweep, 2)
	# Done creating PriorityListAI PriorityList_3
	#########################################
	#########################################
	# Creating ConditionalAI CloseRange at (267, 221)
	## Conditions:
	#### Condition Close
	pClose = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 100.0 + fTargetRadius, pShip.GetName(), sTarget)
	## Evaluation function:
	def EvalFunc(bClose):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bClose:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pCloseRange = App.ConditionalAI_Create(pShip, "CloseRange")
	pCloseRange.SetInterruptable(1)
	pCloseRange.SetContainedAI(pPriorityList_3)
	pCloseRange.AddCondition(pClose)
	pCloseRange.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI CloseRange
	#########################################
	#########################################
	# Creating PlainAI Torprun at (469, 75)
	pTorprun = App.PlainAI_Create(pShip, "Torprun")
	pTorprun.SetScriptModule("TorpedoRun")
	pTorprun.SetInterruptable(1)
	pScript = pTorprun.GetScriptInstance()
	pScript.SetTargetObjectName(sTarget)
	pScript.SetPerpendicularMovementAdjustment(0.7)
	# Done creating PlainAI Torprun
	#########################################
	#########################################
	# Creating PreprocessingAI AttackStatus_LiningUpFront_2 at (467, 130)
	## Setup:
	import AI.Preprocessors
	pPreprocess = AI.Preprocessors.UpdateAIStatus("AttackStatus_LiningUpFront")
	## The PreprocessingAI:
	pAttackStatus_LiningUpFront_2 = App.PreprocessingAI_Create(pShip, "AttackStatus_LiningUpFront_2")
	pAttackStatus_LiningUpFront_2.SetInterruptable(1)
	pAttackStatus_LiningUpFront_2.SetPreprocessingMethod(pPreprocess, "Update")
	pAttackStatus_LiningUpFront_2.SetContainedAI(pTorprun)
	# Done creating PreprocessingAI AttackStatus_LiningUpFront_2
	#########################################
	#########################################
	# Creating ConditionalAI ForwardTorpsReady_2 at (471, 180)
	## Conditions:
	#### Condition TorpsReady
	pTorpsReady = App.ConditionScript_Create("Conditions.ConditionTorpsReady", "ConditionTorpsReady", pShip.GetName(), App.TGPoint3_GetModelForward())
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
	pForwardTorpsReady_2 = App.ConditionalAI_Create(pShip, "ForwardTorpsReady_2")
	pForwardTorpsReady_2.SetInterruptable(1)
	pForwardTorpsReady_2.SetContainedAI(pAttackStatus_LiningUpFront_2)
	pForwardTorpsReady_2.AddCondition(pTorpsReady)
	pForwardTorpsReady_2.AddCondition(pUsingTorps)
	pForwardTorpsReady_2.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI ForwardTorpsReady_2
	#########################################
	#########################################
	# Creating PlainAI PhaserSweep at (577, 180)
	pPhaserSweep = App.PlainAI_Create(pShip, "PhaserSweep")
	pPhaserSweep.SetScriptModule("PhaserSweep")
	pPhaserSweep.SetInterruptable(1)
	pScript = pPhaserSweep.GetScriptInstance()
	pScript.SetTargetObjectName(sTarget)
	pScript.SetSweepPhasersDuringRun(65.0)
	pScript.SetSpeedFraction(1.0)
	pScript.SetPrimaryDirection(App.TGPoint3_GetModelForward())
	# Done creating PlainAI PhaserSweep
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (52, 205)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (238, 285)
	pPriorityList.AddAI(pTooFar, 1)
	pPriorityList.AddAI(pCloseRange, 2)
	pPriorityList.AddAI(pForwardTorpsReady_2, 3)
	pPriorityList.AddAI(pPhaserSweep, 4)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PreprocessingAI AttackStatus_SweepingPhasers at (27, 250)
	## Setup:
	import AI.Preprocessors
	pPreprocess = AI.Preprocessors.UpdateAIStatus("AttackStatus_SweepingPhasers")
	## The PreprocessingAI:
	pAttackStatus_SweepingPhasers = App.PreprocessingAI_Create(pShip, "AttackStatus_SweepingPhasers")
	pAttackStatus_SweepingPhasers.SetInterruptable(1)
	pAttackStatus_SweepingPhasers.SetPreprocessingMethod(pPreprocess, "Update")
	pAttackStatus_SweepingPhasers.SetContainedAI(pPriorityList)
	# Done creating PreprocessingAI AttackStatus_SweepingPhasers
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (26, 300)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pAttackStatus_SweepingPhasers)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	#########################################
	# Creating PreprocessingAI Fire at (23, 348)
	## Setup:
	import AI.Preprocessors
	pFireScript = AI.Preprocessors.FireScript(sTarget, MaxFiringRange = (40.0 / 0.175))
	for pSystem in [ pShip.GetTorpedoSystem(), pShip.GetPhaserSystem(), pShip.GetPulseWeaponSystem() ]:
		if pSystem:
			pFireScript.AddWeaponSystem( pSystem )
	## The PreprocessingAI:
	pFire = App.PreprocessingAI_Create(pShip, "Fire")
	pFire.SetInterruptable(1)
	pFire.SetPreprocessingMethod(pFireScript, "Update")
	pFire.SetContainedAI(pAvoidObstacles)
	# Done creating PreprocessingAI Fire
	#########################################
	#########################################
	# Creating PreprocessingAI SelectTarget at (22, 396)
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
	pSelectTarget.SetContainedAI(pFire)
	# Done creating PreprocessingAI SelectTarget
	#########################################
	#########################################
	# Creating PreprocessingAI FelixReport_DestroyForeClose at (18, 446)
	## Setup:
	import AI.Preprocessors
	pPreprocess = AI.Preprocessors.FelixReportStatus()
	## The PreprocessingAI:
	pFelixReport_DestroyForeClose = App.PreprocessingAI_Create(pShip, "FelixReport_DestroyForeClose")
	pFelixReport_DestroyForeClose.SetInterruptable(1)
	pFelixReport_DestroyForeClose.SetPreprocessingMethod(pPreprocess, "Update")
	pFelixReport_DestroyForeClose.SetContainedAI(pSelectTarget)
	# Done creating PreprocessingAI FelixReport_DestroyForeClose
	#########################################
	return pFelixReport_DestroyForeClose
