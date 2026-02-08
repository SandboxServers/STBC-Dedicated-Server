import App

def CreateAI(pShip, pTarget, vSide):
	if pTarget:
		sTarget = pTarget.GetName()
	else:
		sTarget = ""

	#########################################
	# Creating PlainAI Circle at (109, 164)
	pCircle = App.PlainAI_Create(pShip, "Circle")
	pCircle.SetScriptModule("CircleObject")
	pCircle.SetInterruptable(1)
	pScript = pCircle.GetScriptInstance()
	pScript.SetFollowObjectName(sTarget)
	pScript.SetNearFacingVector(vSide)
	# Done creating PlainAI Circle
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles_DestroyFaceSide at (79, 229)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles_DestroyFaceSide = App.PreprocessingAI_Create(pShip, "AvoidObstacles_DestroyFaceSide")
	pAvoidObstacles_DestroyFaceSide.SetInterruptable(1)
	pAvoidObstacles_DestroyFaceSide.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles_DestroyFaceSide.SetContainedAI(pCircle)
	# Done creating PreprocessingAI AvoidObstacles_DestroyFaceSide
	#########################################
	#########################################
	# Creating PreprocessingAI Fire at (49, 289)
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
	pFire.SetContainedAI(pAvoidObstacles_DestroyFaceSide)
	# Done creating PreprocessingAI Fire
	#########################################
	#########################################
	# Creating PreprocessingAI SelectTarget at (38, 340)
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
