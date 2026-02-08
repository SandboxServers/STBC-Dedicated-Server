import App
def CreateAI(pShip):



	#########################################
	# Creating PlainAI RunLauncherScript at (225, 110)
	pRunLauncherScript = App.PlainAI_Create(pShip, "RunLauncherScript")
	pRunLauncherScript.SetScriptModule("RunScript")
	pRunLauncherScript.SetInterruptable(1)
	pScript = pRunLauncherScript.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode7.E7M3.E7M3")
	pScript.SetFunction("LauncherAttack")
	pScript.SetArguments(pShip.GetName())
	# Done creating PlainAI RunLauncherScript
	#########################################
	#########################################
	# Creating ConditionalAI CloseToFriendly at (185, 65)
	## Conditions:
	#### Condition Close
	pClose = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 150, pShip.GetName(), "player", "USS Geronimo")
	## Evaluation function:
	def EvalFunc(bClose):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if  bClose:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pCloseToFriendly = App.ConditionalAI_Create(pShip, "CloseToFriendly")
	pCloseToFriendly.SetInterruptable(1)
	pCloseToFriendly.SetContainedAI(pRunLauncherScript)
	pCloseToFriendly.AddCondition(pClose)
	pCloseToFriendly.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI CloseToFriendly
	#########################################
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
	# Creating PreprocessingAI Decloak at (242, 13)
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

	#########################################
	# Creating SequenceAI Sequence at (83, 13)
	pSequence = App.SequenceAI_Create(pShip, "Sequence")
	pSequence.SetInterruptable(1)
	pSequence.SetLoopCount(1)
	pSequence.SetResetIfInterrupted(1)
	pSequence.SetDoubleCheckAllDone(0)
	pSequence.SetSkipDormant(0)
	# SeqBlock is at (176, 20)
	pSequence.AddAI(pCloseToFriendly)
	pSequence.AddAI(pDecloak)
	# Done creating SequenceAI Sequence
	#########################################
	return pSequence
