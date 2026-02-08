import App

def CreateAI(pShip, pTarget, vSide, fAngle):
	if pTarget:
		sTarget = pTarget.GetName()
	else:
		sTarget = ""

	#########################################
	# Creating PlainAI PhaserSweep at (63, 189)
	pPhaserSweep = App.PlainAI_Create(pShip, "PhaserSweep")
	pPhaserSweep.SetScriptModule("PhaserSweep")
	pPhaserSweep.SetInterruptable(1)
	pScript = pPhaserSweep.GetScriptInstance()
	pScript.SetTargetObjectName(sTarget)
	pScript.SetSweepPhasersDuringRun(fAngle)
	pScript.SetSpeedFraction(1.0)
	pScript.SetPrimaryDirection(vSide)
	# Done creating PlainAI PhaserSweep
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles_DestroyFromSide at (23, 239)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles_DestroyFromSide = App.PreprocessingAI_Create(pShip, "AvoidObstacles_DestroyFromSide")
	pAvoidObstacles_DestroyFromSide.SetInterruptable(1)
	pAvoidObstacles_DestroyFromSide.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles_DestroyFromSide.SetContainedAI(pPhaserSweep)
	# Done creating PreprocessingAI AvoidObstacles_DestroyFromSide
	#########################################
	#########################################
	# Creating PreprocessingAI Fire at (22, 291)
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
	pFire.SetContainedAI(pAvoidObstacles_DestroyFromSide)
	# Done creating PreprocessingAI Fire
	#########################################
	#########################################
	# Creating PreprocessingAI SelectTarget at (19, 339)
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
