import App
def CreateAI(pShip):



	#########################################
	# Creating PlainAI StationaryAttack at (415, 86)
	pStationaryAttack = App.PlainAI_Create(pShip, "StationaryAttack")
	pStationaryAttack.SetScriptModule("StationaryAttack")
	pStationaryAttack.SetInterruptable(1)
	pScript = pStationaryAttack.GetScriptInstance()
	pScript.SetTargetObjectName("player")
	# Done creating PlainAI StationaryAttack
	#########################################

	#########################################
	# Creating PreprocessingAI Fire at (322, 106)
	## Setup:
	import AI.Preprocessors
	pFireScript = AI.Preprocessors.FireScript("player")
	for pSystem in [pShip.GetTorpedoSystem()]:
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
	# Creating PreprocessingAI SelectTarget at (281, 58)
	## Setup:
	import AI.Preprocessors
	pSelectionPreprocess = AI.Preprocessors.SelectTarget("player", "U.S.S Geronimo")
	pSelectionPreprocess.ForceCurrentTargetString("player")
	## The PreprocessingAI:
	pSelectTarget = App.PreprocessingAI_Create(pShip, "SelectTarget")
	pSelectTarget.SetInterruptable(1)
	pSelectTarget.SetPreprocessingMethod(pSelectionPreprocess, "Update")
	pSelectTarget.SetContainedAI(pFire)
	# Done creating PreprocessingAI SelectTarget
	#########################################
	#########################################
	# Creating PreprocessingAI Decloak at (242, 12)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.CloakShip(0)
	## The PreprocessingAI:
	pDecloak = App.PreprocessingAI_Create(pShip, "Decloak")
	pDecloak.SetInterruptable(1)
	pDecloak.SetPreprocessingMethod(pScript, "Update")
	pDecloak.SetContainedAI(pSelectTarget)
	# Done creating PreprocessingAI Decloak
	#########################################

	return pDecloak
