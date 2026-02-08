import App

def CreateAI(pShip, pTarget):
	if pTarget:
		sTarget = pTarget.GetName()
		fTargetRadius = pTarget.GetRadius()
	else:
		sTarget = ""
		fTargetRadius = 0.0

	#########################################
	# Creating PlainAI EvadeTorps at (213, 11)
	pEvadeTorps = App.PlainAI_Create(pShip, "EvadeTorps")
	pEvadeTorps.SetScriptModule("EvadeTorps")
	pEvadeTorps.SetInterruptable(1)
	# Done creating PlainAI EvadeTorps
	#########################################
	#########################################
	# Creating PreprocessingAI AttackStatus_EvadingTorps at (215, 57)
	## Setup:
	import AI.Preprocessors
	pPreprocess = AI.Preprocessors.UpdateAIStatus("AttackStatus_EvadingTorps1")
	## The PreprocessingAI:
	pAttackStatus_EvadingTorps = App.PreprocessingAI_Create(pShip, "AttackStatus_EvadingTorps")
	pAttackStatus_EvadingTorps.SetInterruptable(1)
	pAttackStatus_EvadingTorps.SetPreprocessingMethod(pPreprocess, "Update")
	pAttackStatus_EvadingTorps.SetContainedAI(pEvadeTorps)
	# Done creating PreprocessingAI AttackStatus_EvadingTorps
	#########################################
	#########################################
	# Creating ConditionalAI IncomingTorps at (214, 107)
	## Conditions:
	#### Condition Incoming
	pIncoming = App.ConditionScript_Create("Conditions.ConditionIncomingTorps", "ConditionIncomingTorps", pShip.GetName(), sTarget)
	## Evaluation function:
	def EvalFunc(bIncoming):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bIncoming:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pIncomingTorps = App.ConditionalAI_Create(pShip, "IncomingTorps")
	pIncomingTorps.SetInterruptable(1)
	pIncomingTorps.SetContainedAI(pAttackStatus_EvadingTorps)
	pIncomingTorps.AddCondition(pIncoming)
	pIncomingTorps.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI IncomingTorps
	#########################################
	#########################################
	# Creating PlainAI DefensiveFlee at (362, 43)
	pDefensiveFlee = App.PlainAI_Create(pShip, "DefensiveFlee")
	pDefensiveFlee.SetScriptModule("IntelligentCircleObject")
	pDefensiveFlee.SetInterruptable(1)
	pScript = pDefensiveFlee.GetScriptInstance()
	pScript.SetFollowObjectName(sTarget)
	pScript.SetShieldAndWeaponImportance(0.8, 0.2)
	pScript.SetForwardBias(-0.5)
	# Done creating PlainAI DefensiveFlee
	#########################################
	#########################################
	# Creating ConditionalAI TooClose at (309, 86)
	## Conditions:
	#### Condition Close
	pClose = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 150.0 + fTargetRadius, pShip.GetName(), sTarget)
	## Evaluation function:
	def EvalFunc(bClose):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bClose:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pTooClose = App.ConditionalAI_Create(pShip, "TooClose")
	pTooClose.SetInterruptable(1)
	pTooClose.SetContainedAI(pDefensiveFlee)
	pTooClose.AddCondition(pClose)
	pTooClose.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI TooClose
	#########################################
	#########################################
	# Creating PlainAI ICO_ShieldBias at (338, 125)
	pICO_ShieldBias = App.PlainAI_Create(pShip, "ICO_ShieldBias")
	pICO_ShieldBias.SetScriptModule("IntelligentCircleObject")
	pICO_ShieldBias.SetInterruptable(1)
	pScript = pICO_ShieldBias.GetScriptInstance()
	pScript.SetFollowObjectName(sTarget)
	pScript.UseFixedCode(1)
	pScript.SetShieldAndWeaponImportance(0.95, 0.05)
	# Done creating PlainAI ICO_ShieldBias
	#########################################

	#########################################
	# Creating PriorityListAI PriorityList at (170, 169)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (281, 175)
	pPriorityList.AddAI(pIncomingTorps, 1)
	pPriorityList.AddAI(pTooClose, 2)
	pPriorityList.AddAI(pICO_ShieldBias, 3)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PreprocessingAI UsetShipTarget at (78, 173)
	## Setup:
	import AI.Preprocessors
	pPreprocess = AI.Preprocessors.UseShipTarget()
	## The PreprocessingAI:
	pUsetShipTarget = App.PreprocessingAI_Create(pShip, "UsetShipTarget")
	pUsetShipTarget.SetInterruptable(1)
	pUsetShipTarget.SetPreprocessingMethod(pPreprocess, "Update")
	pUsetShipTarget.SetContainedAI(pPriorityList)
	# Done creating PreprocessingAI UsetShipTarget
	#########################################
	#########################################
	# Creating PlainAI Maneuver1 at (360, 165)
	pManeuver1 = App.PlainAI_Create(pShip, "Maneuver1")
	pManeuver1.SetScriptModule("ManeuverLoop")
	pManeuver1.SetInterruptable(1)
	pScript = pManeuver1.GetScriptInstance()
	pScript.SetLoopFraction(0.125)
	pScript.SetTurnAxis(App.TGPoint3_GetModelLeft())
	# Done creating PlainAI Maneuver1
	#########################################
	#########################################
	# Creating PlainAI Maneuver2 at (448, 164)
	pManeuver2 = App.PlainAI_Create(pShip, "Maneuver2")
	pManeuver2.SetScriptModule("ManeuverLoop")
	pManeuver2.SetInterruptable(1)
	pScript = pManeuver2.GetScriptInstance()
	pScript.SetLoopFraction(0.125)
	pScript.SetTurnAxis(App.TGPoint3_GetModelRight())
	# Done creating PlainAI Maneuver2
	#########################################
	#########################################
	# Creating PlainAI Maneuver3 at (509, 206)
	pManeuver3 = App.PlainAI_Create(pShip, "Maneuver3")
	pManeuver3.SetScriptModule("ManeuverLoop")
	pManeuver3.SetInterruptable(1)
	pScript = pManeuver3.GetScriptInstance()
	pScript.SetLoopFraction(0.125)
	pScript.SetTurnAxis(App.TGPoint3_GetModelUp())
	# Done creating PlainAI Maneuver3
	#########################################
	#########################################
	# Creating PlainAI Maneuver4 at (512, 289)
	pManeuver4 = App.PlainAI_Create(pShip, "Maneuver4")
	pManeuver4.SetScriptModule("ManeuverLoop")
	pManeuver4.SetInterruptable(1)
	pScript = pManeuver4.GetScriptInstance()
	pScript.SetLoopFraction(0.125)
	pScript.SetTurnAxis(App.TGPoint3_GetModelDown())
	# Done creating PlainAI Maneuver4
	#########################################
	#########################################
	# Creating RandomAI Random at (323, 253)
	pRandom = App.RandomAI_Create(pShip, "Random")
	pRandom.SetInterruptable(1)
	# SeqBlock is at (442, 265)
	pRandom.AddAI(pManeuver1)
	pRandom.AddAI(pManeuver2)
	pRandom.AddAI(pManeuver3)
	pRandom.AddAI(pManeuver4)
	# Done creating RandomAI Random
	#########################################
	#########################################
	# Creating SequenceAI RepeatForever at (223, 287)
	pRepeatForever = App.SequenceAI_Create(pShip, "RepeatForever")
	pRepeatForever.SetInterruptable(1)
	pRepeatForever.SetLoopCount(-1)
	pRepeatForever.SetResetIfInterrupted(1)
	pRepeatForever.SetDoubleCheckAllDone(1)
	pRepeatForever.SetSkipDormant(0)
	# SeqBlock is at (330, 294)
	pRepeatForever.AddAI(pRandom)
	# Done creating SequenceAI RepeatForever
	#########################################
	#########################################
	# Creating PriorityListAI TargetOrNoTarget at (16, 220)
	pTargetOrNoTarget = App.PriorityListAI_Create(pShip, "TargetOrNoTarget")
	pTargetOrNoTarget.SetInterruptable(1)
	# SeqBlock is at (163, 290)
	pTargetOrNoTarget.AddAI(pUsetShipTarget, 1)
	pTargetOrNoTarget.AddAI(pRepeatForever, 2)
	# Done creating PriorityListAI TargetOrNoTarget
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles_Defense at (19, 267)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles_Defense = App.PreprocessingAI_Create(pShip, "AvoidObstacles_Defense")
	pAvoidObstacles_Defense.SetInterruptable(1)
	pAvoidObstacles_Defense.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles_Defense.SetContainedAI(pTargetOrNoTarget)
	# Done creating PreprocessingAI AvoidObstacles_Defense
	#########################################
	#########################################
	# Creating PreprocessingAI SelectTarget at (19, 316)
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
	pSelectTarget.SetPreprocessingMethod(pSelectionPreprocess, "Update()")
	pSelectTarget.SetContainedAI(pAvoidObstacles_Defense)
	# Done creating PreprocessingAI SelectTarget
	#########################################
	#########################################
	# Creating PreprocessingAI FelixReport at (17, 363)
	## Setup:
	import AI.Preprocessors
	pPreprocess = AI.Preprocessors.FelixReportStatus()
	## The PreprocessingAI:
	pFelixReport = App.PreprocessingAI_Create(pShip, "FelixReport")
	pFelixReport.SetInterruptable(1)
	pFelixReport.SetPreprocessingMethod(pPreprocess, "Update")
	pFelixReport.SetContainedAI(pSelectTarget)
	# Done creating PreprocessingAI FelixReport
	#########################################
	return pFelixReport
