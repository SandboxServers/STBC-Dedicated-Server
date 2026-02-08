import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI StationaryAttack at (279, 132)
	pStationaryAttack = App.PlainAI_Create(pShip, "StationaryAttack")
	pStationaryAttack.SetScriptModule("StationaryAttack")
	pStationaryAttack.SetInterruptable(1)
	pScript = pStationaryAttack.GetScriptInstance()
	pScript.SetTargetObjectName("USS Berkeley")
	# Done creating PlainAI StationaryAttack
	#########################################
	#########################################
	# Creating PreprocessingAI Fire at (197, 153)
	## Setup:
	import AI.Preprocessors
	pFireScript = AI.Preprocessors.FireScript("USS Berkeley")
	for pSystem in [pShip.GetPhaserSystem(), pShip.GetPulseWeaponSystem()]:
		if pSystem:
			pFireScript.AddWeaponSystem( pSystem )
	## The PreprocessingAI:
	pFire = App.PreprocessingAI_Create(pShip, "Fire")
	pFire.SetInterruptable(1)
	pFire.SetPreprocessingMethod(pFireScript, "Update")
	pFire.SetContainedAI(pStationaryAttack)
	# Done creating PreprocessingAI Fire
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (110, 63)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pFire)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
