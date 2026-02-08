import App

def CreateAI(pShip, pTarget, vSide):
	if pTarget:
		sTarget = pTarget.GetName()
	else:
		sTarget = ""

	lTargetSubsystems = [
		(App.CT_IMPULSE_ENGINE_SUBSYSTEM, 2),
		(App.CT_WARP_ENGINE_SUBSYSTEM, 2),
		(App.CT_WEAPON_SYSTEM, 1) ]


	#########################################
	# Creating PlainAI Circle at (63, 189)
	pCircle = App.PlainAI_Create(pShip, "Circle")
	pCircle.SetScriptModule("CircleObject")
	pCircle.SetInterruptable(1)
	pScript = pCircle.GetScriptInstance()
	pScript.SetFollowObjectName(sTarget)
	pScript.SetNearFacingVector(vSide)
	# Done creating PlainAI Circle
	#########################################
	#########################################
	# Creating PreprocessingAI Fire at (52, 242)
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
	pFire.SetContainedAI(pCircle)
	# Done creating PreprocessingAI Fire
	#########################################
	#########################################
	# Creating PreprocessingAI SelectTarget at (37, 296)
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
	# Creating PreprocessingAI AvoidObstacles_DisableFaceSide at (24, 358)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles_DisableFaceSide = App.PreprocessingAI_Create(pShip, "AvoidObstacles_DisableFaceSide")
	pAvoidObstacles_DisableFaceSide.SetInterruptable(1)
	pAvoidObstacles_DisableFaceSide.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles_DisableFaceSide.SetContainedAI(pSelectTarget)
	# Done creating PreprocessingAI AvoidObstacles_DisableFaceSide
	#########################################
	return pAvoidObstacles_DisableFaceSide
