import App

def CreateAI(pShip, pTarget):
	if pTarget:
		sTarget = pTarget.GetName()
	else:
		sTarget = ""

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
	# Creating PreprocessingAI AvoidObstacles_DestroyAftSeparate at (33, 263)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles_DestroyAftSeparate = App.PreprocessingAI_Create(pShip, "AvoidObstacles_DestroyAftSeparate")
	pAvoidObstacles_DestroyAftSeparate.SetInterruptable(1)
	pAvoidObstacles_DestroyAftSeparate.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles_DestroyAftSeparate.SetContainedAI(pFlyAway)
	# Done creating PreprocessingAI AvoidObstacles_DestroyAftSeparate
	#########################################
	#########################################
	# Creating PreprocessingAI Fire at (25, 313)
	## Setup:
	import AI.Preprocessors
	pFireScript = AI.Preprocessors.FireScript(sTarget)
	for pSystem in [ pShip.GetTorpedoSystem(), pShip.GetPhaserSystem(), pShip.GetPulseWeaponSystem() ]:
		if pSystem:
			pFireScript.AddWeaponSystem( pSystem )
	## The PreprocessingAI:
	pFire = App.PreprocessingAI_Create(pShip, "Fire")
	pFire.SetInterruptable(1)
	pFire.SetPreprocessingMethod(pFireScript, "Update")
	pFire.SetContainedAI(pAvoidObstacles_DestroyAftSeparate)
	# Done creating PreprocessingAI Fire
	#########################################
	#########################################
	# Creating PreprocessingAI SelectTarget at (14, 372)
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
	return pSelectTarget
