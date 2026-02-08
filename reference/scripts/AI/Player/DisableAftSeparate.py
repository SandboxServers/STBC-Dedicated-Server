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
	# Creating PlainAI FlyAway at (48, 216)
	pFlyAway = App.PlainAI_Create(pShip, "FlyAway")
	pFlyAway.SetScriptModule("TorpedoRun")
	pFlyAway.SetInterruptable(1)
	pScript = pFlyAway.GetScriptInstance()
	pScript.SetTargetObjectName(sTarget)
	pScript.SetTorpDirection(App.TGPoint3_GetModelBackward())
	# Done creating PlainAI FlyAway
	#########################################
	#########################################
	# Creating PreprocessingAI Fire at (39, 270)
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
	pFire.SetContainedAI(pFlyAway)
	# Done creating PreprocessingAI Fire
	#########################################
	#########################################
	# Creating PreprocessingAI SelectTarget at (24, 312)
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
	# Creating PreprocessingAI AvoidObstacles_DisableAftSeparate at (24, 358)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles_DisableAftSeparate = App.PreprocessingAI_Create(pShip, "AvoidObstacles_DisableAftSeparate")
	pAvoidObstacles_DisableAftSeparate.SetInterruptable(1)
	pAvoidObstacles_DisableAftSeparate.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles_DisableAftSeparate.SetContainedAI(pSelectTarget)
	# Done creating PreprocessingAI AvoidObstacles_DisableAftSeparate
	#########################################
	return pAvoidObstacles_DisableAftSeparate
