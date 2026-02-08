import App

def CreateAI(pShip):
	#########################################
	# Creating PlainAI Stay_2 at (6, 272)
	pStay_2 = App.PlainAI_Create(pShip, "Stay_2")
	pStay_2.SetScriptModule("Stay")
	pStay_2.SetInterruptable(1)
	# Done creating PlainAI Stay_2
	#########################################
	#########################################
	# Creating ConditionalAI PlayerNotInRangeYet at (9, 229)
	## Conditions:
	#### Condition InRange
	pInRange = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 1000, pShip.GetName(), "player")
	#### Condition SameSet
	pSameSet = App.ConditionScript_Create("Conditions.ConditionAllInSameSet", "ConditionAllInSameSet", pShip.GetName(), "player")
	## Evaluation function:
	def EvalFunc(bInRange, bSameSet):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bSameSet and bInRange:
			return DONE
		return ACTIVE
	## The ConditionalAI:
	pPlayerNotInRangeYet = App.ConditionalAI_Create(pShip, "PlayerNotInRangeYet")
	pPlayerNotInRangeYet.SetInterruptable(1)
	pPlayerNotInRangeYet.SetContainedAI(pStay_2)
	pPlayerNotInRangeYet.AddCondition(pInRange)
	pPlayerNotInRangeYet.AddCondition(pSameSet)
	pPlayerNotInRangeYet.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI PlayerNotInRangeYet
	#########################################
	#########################################
	# Creating PlainAI TellPlayer at (123, 352)
	pTellPlayer = App.PlainAI_Create(pShip, "TellPlayer")
	pTellPlayer.SetScriptModule("RunScript")
	pTellPlayer.SetInterruptable(1)
	pScript = pTellPlayer.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode4.E4M6.E4M6")
	pScript.SetFunction("RihaGalorEscaped")
	# Done creating PlainAI TellPlayer
	#########################################
	#########################################
	# Creating PlainAI Warp at (204, 349)
	pWarp = App.PlainAI_Create(pShip, "Warp")
	pWarp.SetScriptModule("Warp")
	pWarp.SetInterruptable(1)
	# Done creating PlainAI Warp
	#########################################
	#########################################
	# Creating SequenceAI Sequence at (107, 292)
	pSequence = App.SequenceAI_Create(pShip, "Sequence")
	pSequence.SetInterruptable(1)
	pSequence.SetLoopCount(1)
	pSequence.SetResetIfInterrupted(1)
	pSequence.SetDoubleCheckAllDone(0)
	pSequence.SetSkipDormant(0)
	# SeqBlock is at (199, 315)
	pSequence.AddAI(pTellPlayer)
	pSequence.AddAI(pWarp)
	# Done creating SequenceAI Sequence
	#########################################
	#########################################
	# Creating ConditionalAI FarAway at (116, 243)
	## Conditions:
	#### Condition SameSet
	pSameSet = App.ConditionScript_Create("Conditions.ConditionAllInSameSet", "ConditionAllInSameSet", pShip.GetName(), "player")
	#### Condition InRange
	pInRange = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 1000, pShip.GetName(), "player")
	## Evaluation function:
	def EvalFunc(bSameSet, bInRange):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bSameSet and not bInRange:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pFarAway = App.ConditionalAI_Create(pShip, "FarAway")
	pFarAway.SetInterruptable(1)
	pFarAway.SetContainedAI(pSequence)
	pFarAway.AddCondition(pSameSet)
	pFarAway.AddCondition(pInRange)
	pFarAway.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI FarAway
	#########################################
	#########################################
	# Creating PlainAI RunFromPlayer at (293, 341)
	pRunFromPlayer = App.PlainAI_Create(pShip, "RunFromPlayer")
	pRunFromPlayer.SetScriptModule("Flee")
	pRunFromPlayer.SetInterruptable(1)
	pScript = pRunFromPlayer.GetScriptInstance()
	pScript.SetFleeFromGroup("player")
	# Done creating PlainAI RunFromPlayer
	#########################################
	#########################################
	# Creating PreprocessingAI FireOnPlayer at (291, 299)
	## Setup:
	import AI.Preprocessors
	pFireScript = AI.Preprocessors.FireScript("player")
	for pSystem in [ pShip.GetTorpedoSystem(), pShip.GetPhaserSystem(), pShip.GetPulseWeaponSystem() ]:
		if pSystem:
			pFireScript.AddWeaponSystem( pSystem )
	## The PreprocessingAI:
	pFireOnPlayer = App.PreprocessingAI_Create(pShip, "FireOnPlayer")
	pFireOnPlayer.SetInterruptable(1)
	pFireOnPlayer.SetPreprocessingMethod(pFireScript, "Update")
	pFireOnPlayer.SetContainedAI(pRunFromPlayer)
	# Done creating PreprocessingAI FireOnPlayer
	#########################################
	#########################################
	# Creating ConditionalAI InPlayerSet at (292, 255)
	## Conditions:
	#### Condition SameSet
	pSameSet = App.ConditionScript_Create("Conditions.ConditionAllInSameSet", "ConditionAllInSameSet", pShip.GetName(), "player")
	## Evaluation function:
	def EvalFunc(bSameSet):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bSameSet:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pInPlayerSet = App.ConditionalAI_Create(pShip, "InPlayerSet")
	pInPlayerSet.SetInterruptable(1)
	pInPlayerSet.SetContainedAI(pFireOnPlayer)
	pInPlayerSet.AddCondition(pSameSet)
	pInPlayerSet.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI InPlayerSet
	#########################################
	#########################################
	# Creating PlainAI Stay at (434, 254)
	pStay = App.PlainAI_Create(pShip, "Stay")
	pStay.SetScriptModule("Stay")
	pStay.SetInterruptable(1)
	# Done creating PlainAI Stay
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (226, 180)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (391, 214)
	pPriorityList.AddAI(pInPlayerSet, 1)
	pPriorityList.AddAI(pStay, 2)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating ConditionalAI IfNotDamaged at (226, 133)
	## Conditions:
	#### Condition HullLow
	pHullLow = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName(),App.CT_HULL_SUBSYSTEM,0.50)
	#### Condition PowerSystemLow
	pPowerSystemLow = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName(), App.CT_POWER_SUBSYSTEM, 0.50)
	#### Condition Disabled
	pDisabled = App.ConditionScript_Create("Conditions.ConditionShipDisabled", "ConditionShipDisabled", "G5")
	## Evaluation function:
	def EvalFunc(bHullLow, bPowerSystemLow, bDisabled):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bHullLow or bPowerSystemLow or bDisabled:
			return DORMANT
		else:
			return ACTIVE
	## The ConditionalAI:
	pIfNotDamaged = App.ConditionalAI_Create(pShip, "IfNotDamaged")
	pIfNotDamaged.SetInterruptable(1)
	pIfNotDamaged.SetContainedAI(pPriorityList)
	pIfNotDamaged.AddCondition(pHullLow)
	pIfNotDamaged.AddCondition(pPowerSystemLow)
	pIfNotDamaged.AddCondition(pDisabled)
	pIfNotDamaged.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI IfNotDamaged
	#########################################
	#########################################
	# Creating PlainAI KlingonAttack at (448, 143)
	pKlingonAttack = App.PlainAI_Create(pShip, "KlingonAttack")
	pKlingonAttack.SetScriptModule("RunScript")
	pKlingonAttack.SetInterruptable(1)
	pScript = pKlingonAttack.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode4.E4M6.E4M6")
	pScript.SetFunction("BOPAttack")
	# Done creating PlainAI KlingonAttack
	#########################################
	#########################################
	# Creating PriorityListAI RihaGalorAI at (183, 24)
	pRihaGalorAI = App.PriorityListAI_Create(pShip, "RihaGalorAI")
	pRihaGalorAI.SetInterruptable(1)
	# SeqBlock is at (215, 85)
	pRihaGalorAI.AddAI(pPlayerNotInRangeYet, 1)
	pRihaGalorAI.AddAI(pFarAway, 2)
	pRihaGalorAI.AddAI(pIfNotDamaged, 3)
	pRihaGalorAI.AddAI(pKlingonAttack, 4)
	# Done creating PriorityListAI RihaGalorAI
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (10, 42)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pRihaGalorAI)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
