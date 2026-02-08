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
	# Creating PlainAI TorpedoRun at (317, 164)
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
	# Creating PreprocessingAI AttackStatus_LiningUpFront at (320, 217)
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
	# Creating ConditionalAI ForwardTorpsReady_2 at (323, 265)
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
	# Creating PlainAI ICOWeapons at (425, 266)
	pICOWeapons = App.PlainAI_Create(pShip, "ICOWeapons")
	pICOWeapons.SetScriptModule("IntelligentCircleObject")
	pICOWeapons.SetInterruptable(1)
	pScript = pICOWeapons.GetScriptInstance()
	pScript.SetFollowObjectName(sTarget)
	pScript.SetShieldAndWeaponImportance(0.1, 0.9)
	# Done creating PlainAI ICOWeapons
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (50, 211)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (392, 332)
	pPriorityList.AddAI(pForwardTorpsReady_2, 1)
	pPriorityList.AddAI(pICOWeapons, 2)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles_DisableFreelyMaintain at (13, 258)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles_DisableFreelyMaintain = App.PreprocessingAI_Create(pShip, "AvoidObstacles_DisableFreelyMaintain")
	pAvoidObstacles_DisableFreelyMaintain.SetInterruptable(1)
	pAvoidObstacles_DisableFreelyMaintain.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles_DisableFreelyMaintain.SetContainedAI(pPriorityList)
	# Done creating PreprocessingAI AvoidObstacles_DisableFreelyMaintain
	#########################################
	#########################################
	# Creating PreprocessingAI Fire at (10, 310)
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
	pFire.SetContainedAI(pAvoidObstacles_DisableFreelyMaintain)
	# Done creating PreprocessingAI Fire
	#########################################
	#########################################
	# Creating PreprocessingAI SelectTarget at (8, 365)
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
	# Creating PreprocessingAI FelixReport at (108, 368)
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
