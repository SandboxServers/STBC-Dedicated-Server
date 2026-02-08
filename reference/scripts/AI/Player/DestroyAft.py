import App

def CreateAI(pShip, pTarget):
	if pTarget:
		sTarget = pTarget.GetName()
	else:
		sTarget = ""

	#########################################
	# Creating PlainAI FaceAway at (42, 219)
	pFaceAway = App.PlainAI_Create(pShip, "FaceAway")
	pFaceAway.SetScriptModule("TurnToOrientation")
	pFaceAway.SetInterruptable(1)
	pScript = pFaceAway.GetScriptInstance()
	pScript.SetObjectName(sTarget)
	pScript.SetPrimaryDirection(App.TGPoint3_GetModelBackward())
	# Done creating PlainAI FaceAway
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles_DestroyAft at (41, 269)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles_DestroyAft = App.PreprocessingAI_Create(pShip, "AvoidObstacles_DestroyAft")
	pAvoidObstacles_DestroyAft.SetInterruptable(1)
	pAvoidObstacles_DestroyAft.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles_DestroyAft.SetContainedAI(pFaceAway)
	# Done creating PreprocessingAI AvoidObstacles_DestroyAft
	#########################################
	#########################################
	# Creating PreprocessingAI Fire at (35, 320)
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
	pFire.SetContainedAI(pAvoidObstacles_DestroyAft)
	# Done creating PreprocessingAI Fire
	#########################################
	#########################################
	# Creating PreprocessingAI SelectTarget at (27, 364)
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
