import App

def CreateAI(pShip, pTarget):
	if pTarget:
		sTarget = pTarget.GetName()
	else:
		sTarget = ""

	lTargetSubsystems = [
		(App.CT_IMPULSE_ENGINE_SUBSYSTEM, 2),
		(App.CT_WARP_ENGINE_SUBSYSTEM, 2),
		(App.CT_WEAPON_SYSTEM, 1) ]

	#########################################
	# Creating PlainAI FlyAway at (343, 158)
	pFlyAway = App.PlainAI_Create(pShip, "FlyAway")
	pFlyAway.SetScriptModule("TorpedoRun")
	pFlyAway.SetInterruptable(1)
	pScript = pFlyAway.GetScriptInstance()
	pScript.SetTargetObjectName(sTarget)
	pScript.SetTorpDirection(App.TGPoint3_GetModelBackward())
	# Done creating PlainAI FlyAway
	#########################################
	#########################################
	# Creating PreprocessingAI AttackStatus_RearTorpRun at (343, 211)
	## Setup:
	import AI.Preprocessors
	pPreprocess = AI.Preprocessors.UpdateAIStatus("AttackStatus_RearTorpRun")
	## The PreprocessingAI:
	pAttackStatus_RearTorpRun = App.PreprocessingAI_Create(pShip, "AttackStatus_RearTorpRun")
	pAttackStatus_RearTorpRun.SetInterruptable(1)
	pAttackStatus_RearTorpRun.SetPreprocessingMethod(pPreprocess, "Update")
	pAttackStatus_RearTorpRun.SetContainedAI(pFlyAway)
	# Done creating PreprocessingAI AttackStatus_RearTorpRun
	#########################################
	#########################################
	# Creating ConditionalAI RearTorpsReady_2 at (342, 263)
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
	pRearTorpsReady_2 = App.ConditionalAI_Create(pShip, "RearTorpsReady_2")
	pRearTorpsReady_2.SetInterruptable(1)
	pRearTorpsReady_2.SetContainedAI(pAttackStatus_RearTorpRun)
	pRearTorpsReady_2.AddCondition(pTorpsReady)
	pRearTorpsReady_2.AddCondition(pUsingTorps)
	pRearTorpsReady_2.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI RearTorpsReady_2
	#########################################
	#########################################
	# Creating PlainAI TorpedoRun at (437, 158)
	pTorpedoRun = App.PlainAI_Create(pShip, "TorpedoRun")
	pTorpedoRun.SetScriptModule("TorpedoRun")
	pTorpedoRun.SetInterruptable(1)
	pScript = pTorpedoRun.GetScriptInstance()
	pScript.SetTargetObjectName(sTarget)
	pScript.SetPerpendicularMovementAdjustment(fSpeedFactor = 0.25)
	pScript.SetTorpDirection(vDirection = App.TGPoint3_GetModelForward())
	# Done creating PlainAI TorpedoRun
	#########################################
	#########################################
	# Creating PreprocessingAI AttackStatus_LiningUpFront at (436, 212)
	## Setup:
	import AI.Preprocessors
	pPreprocess = AI.Preprocessors.UpdateAIStatus("AttackStatus_LiningUpFront")
	## The PreprocessingAI:
	pAttackStatus_LiningUpFront = App.PreprocessingAI_Create(pShip, "AttackStatus_LiningUpFront")
	pAttackStatus_LiningUpFront.SetInterruptable(1)
	pAttackStatus_LiningUpFront.SetPreprocessingMethod(pPreprocess, "Update")
	pAttackStatus_LiningUpFront.SetContainedAI(pTorpedoRun)
	# Done creating PreprocessingAI AttackStatus_LiningUpFront
	#########################################
	#########################################
	# Creating ConditionalAI ForwardTorpsReady_2 at (436, 262)
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
	pForwardTorpsReady_2.SetContainedAI(pAttackStatus_LiningUpFront)
	pForwardTorpsReady_2.AddCondition(pTorpsReady)
	pForwardTorpsReady_2.AddCondition(pUsingTorps)
	pForwardTorpsReady_2.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI ForwardTorpsReady_2
	#########################################
	#########################################
	# Creating PlainAI RearPhaserSweep at (468, 325)
	pRearPhaserSweep = App.PlainAI_Create(pShip, "RearPhaserSweep")
	pRearPhaserSweep.SetScriptModule("PhaserSweep")
	pRearPhaserSweep.SetInterruptable(1)
	pScript = pRearPhaserSweep.GetScriptInstance()
	pScript.SetTargetObjectName(sTarget)
	pScript.SetSweepPhasersDuringRun(120.0)
	pScript.SetSpeedFraction(0.5)
	pScript.SetPrimaryDirection(App.TGPoint3_GetModelBackward())
	# Done creating PlainAI RearPhaserSweep
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList_2 at (45, 187)
	pPriorityList_2 = App.PriorityListAI_Create(pShip, "PriorityList_2")
	pPriorityList_2.SetInterruptable(1)
	# SeqBlock is at (392, 332)
	pPriorityList_2.AddAI(pRearTorpsReady_2, 1)
	pPriorityList_2.AddAI(pForwardTorpsReady_2, 2)
	pPriorityList_2.AddAI(pRearPhaserSweep, 3)
	# Done creating PriorityListAI PriorityList_2
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles_DisableFreelySeparate at (0, 263)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles_DisableFreelySeparate = App.PreprocessingAI_Create(pShip, "AvoidObstacles_DisableFreelySeparate")
	pAvoidObstacles_DisableFreelySeparate.SetInterruptable(1)
	pAvoidObstacles_DisableFreelySeparate.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles_DisableFreelySeparate.SetContainedAI(pPriorityList_2)
	# Done creating PreprocessingAI AvoidObstacles_DisableFreelySeparate
	#########################################
	#########################################
	# Creating PreprocessingAI Fire at (3, 320)
	## Setup:
	import AI.Preprocessors
	pFireScript = AI.Preprocessors.FireScript(sTarget, TargetSubsystems=lTargetSubsystems)
	for pSystem in [ pShip.GetTorpedoSystem(), pShip.GetPhaserSystem(), pShip.GetPulseWeaponSystem() ]:
		if pSystem:
			pFireScript.AddWeaponSystem( pSystem )
	pFireScript.UsePlayerSettings(1)
	## The PreprocessingAI:
	pFire = App.PreprocessingAI_Create(pShip, "Fire")
	pFire.SetInterruptable(1)
	pFire.SetPreprocessingMethod(pFireScript, "Update")
	pFire.SetContainedAI(pAvoidObstacles_DisableFreelySeparate)
	# Done creating PreprocessingAI Fire
	#########################################
	#########################################
	# Creating PreprocessingAI SelectTarget at (4, 366)
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
	# Creating PreprocessingAI FelixReport at (103, 368)
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
