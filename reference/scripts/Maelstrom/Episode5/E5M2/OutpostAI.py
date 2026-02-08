import App

def CreateAI(pShip):
	#########################################
	# Creating PlainAI BaseAppearsOnSensors at (113, 114)
	pBaseAppearsOnSensors = App.PlainAI_Create(pShip, "BaseAppearsOnSensors")
	pBaseAppearsOnSensors.SetScriptModule("RunScript")
	pBaseAppearsOnSensors.SetInterruptable(1)
	pScript = pBaseAppearsOnSensors.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode5.E5M2.E5M2")
	pScript.SetFunction("BaseAppears")
	# Done creating PlainAI BaseAppearsOnSensors
	#########################################
	#########################################
	# Creating ConditionalAI InDetectionRange at (113, 80)
	## Conditions:
	#### Condition OutpostRange
	pOutpostRange = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 1500, "player", "Outpost")
	#### Condition LOS
	pLOS = App.ConditionScript_Create("Conditions.ConditionInLineOfSight", "ConditionInLineOfSight", "player", "Outpost", "Moon 2")
	## Evaluation function:
	def EvalFunc(bOutpostRange, bLOS):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bOutpostRange) and not (bLOS):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pInDetectionRange = App.ConditionalAI_Create(pShip, "InDetectionRange")
	pInDetectionRange.SetInterruptable(1)
	pInDetectionRange.SetContainedAI(pBaseAppearsOnSensors)
	pInDetectionRange.AddCondition(pOutpostRange)
	pInDetectionRange.AddCondition(pLOS)
	pInDetectionRange.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI InDetectionRange
	#########################################
	#########################################
	# Creating PlainAI PlayerClosetoBase at (201, 113)
	pPlayerClosetoBase = App.PlainAI_Create(pShip, "PlayerClosetoBase")
	pPlayerClosetoBase.SetScriptModule("RunScript")
	pPlayerClosetoBase.SetInterruptable(1)
	pScript = pPlayerClosetoBase.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode5.E5M2.E5M2")
	pScript.SetFunction("BaseInScanningRange")
	# Done creating PlainAI PlayerClosetoBase
	#########################################
	#########################################
	# Creating ConditionalAI PlayerInScanningRange at (200, 80)
	## Conditions:
	#### Condition InScanningRange
	pInScanningRange = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 1150, "Outpost", "player")
	## Evaluation function:
	def EvalFunc(bInScanningRange):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bInScanningRange:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pPlayerInScanningRange = App.ConditionalAI_Create(pShip, "PlayerInScanningRange")
	pPlayerInScanningRange.SetInterruptable(1)
	pPlayerInScanningRange.SetContainedAI(pPlayerClosetoBase)
	pPlayerInScanningRange.AddCondition(pInScanningRange)
	pPlayerInScanningRange.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI PlayerInScanningRange
	#########################################
	#########################################
	# Creating PlainAI BaseActivate at (285, 113)
	pBaseActivate = App.PlainAI_Create(pShip, "BaseActivate")
	pBaseActivate.SetScriptModule("RunScript")
	pBaseActivate.SetInterruptable(1)
	pScript = pBaseActivate.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode5.E5M2.E5M2")
	pScript.SetFunction("BasePowersUp")
	pScript.SetArguments(None)
	# Done creating PlainAI BaseActivate
	#########################################
	#########################################
	# Creating ConditionalAI InActivationRange at (285, 80)
	## Conditions:
	#### Condition InRange
	pInRange = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 475, "Outpost", "player")
	#### Condition Hit
	pHit = App.ConditionScript_Create("Conditions.ConditionAttacked", "ConditionAttacked", "Outpost", 0, 0, 1000)
	## Evaluation function:
	def EvalFunc(bInRange, bHit):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bHit:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pInActivationRange = App.ConditionalAI_Create(pShip, "InActivationRange")
	pInActivationRange.SetInterruptable(1)
	pInActivationRange.SetContainedAI(pBaseActivate)
	pInActivationRange.AddCondition(pInRange)
	pInActivationRange.AddCondition(pHit)
	pInActivationRange.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI InActivationRange
	#########################################
	#########################################
	# Creating PlainAI OutpostDisabledFunc at (369, 166)
	pOutpostDisabledFunc = App.PlainAI_Create(pShip, "OutpostDisabledFunc")
	pOutpostDisabledFunc.SetScriptModule("RunScript")
	pOutpostDisabledFunc.SetInterruptable(1)
	pScript = pOutpostDisabledFunc.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode5.E5M2.E5M2")
	pScript.SetFunction("OutpostPhasersOut")
	# Done creating PlainAI OutpostDisabledFunc
	#########################################
	#########################################
	# Creating PlainAI Stay at (369, 199)
	pStay = App.PlainAI_Create(pShip, "Stay")
	pStay.SetScriptModule("Stay")
	pStay.SetInterruptable(1)
	# Done creating PlainAI Stay
	#########################################
	#########################################
	# Creating SequenceAI Sequence_2 at (369, 114)
	pSequence_2 = App.SequenceAI_Create(pShip, "Sequence_2")
	pSequence_2.SetInterruptable(1)
	pSequence_2.SetLoopCount(1)
	pSequence_2.SetResetIfInterrupted(1)
	pSequence_2.SetDoubleCheckAllDone(0)
	pSequence_2.SetSkipDormant(0)
	# SeqBlock is at (369, 147)
	pSequence_2.AddAI(pOutpostDisabledFunc)
	pSequence_2.AddAI(pStay)
	# Done creating SequenceAI Sequence_2
	#########################################
	#########################################
	# Creating ConditionalAI OutpostCheck at (369, 80)
	## Conditions:
	#### Condition PhasersGone
	pPhasersGone = App.ConditionScript_Create("Conditions.ConditionSystemDisabled", "ConditionSystemDisabled", "Outpost", App.CT_PHASER_SYSTEM, 1)
	#### Condition PowerLow
	pPowerLow = App.ConditionScript_Create("Conditions.ConditionSystemDisabled", "ConditionSystemDisabled", "Outpost", App.CT_POWER_SUBSYSTEM, 0)
	#### Condition DisruptGone
	pDisruptGone = App.ConditionScript_Create("Conditions.ConditionSystemDisabled", "ConditionSystemDisabled", "Outpost",  App.CT_PULSE_WEAPON_SYSTEM, 1)
	#### Condition SensorsGone
	pSensorsGone = App.ConditionScript_Create("Conditions.ConditionSystemDisabled", "ConditionSystemDisabled", "Outpost", App.CT_SENSOR_SUBSYSTEM, 1)
	## Evaluation function:
	def EvalFunc(bPhasersGone, bPowerLow, bDisruptGone, bSensorsGone):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if ((bPhasersGone) and (bDisruptGone)) or (bPowerLow) or (bSensorsGone):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pOutpostCheck = App.ConditionalAI_Create(pShip, "OutpostCheck")
	pOutpostCheck.SetInterruptable(1)
	pOutpostCheck.SetContainedAI(pSequence_2)
	pOutpostCheck.AddCondition(pPhasersGone)
	pOutpostCheck.AddCondition(pPowerLow)
	pOutpostCheck.AddCondition(pDisruptGone)
	pOutpostCheck.AddCondition(pSensorsGone)
	pOutpostCheck.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI OutpostCheck
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (12, 16)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (285, 22)
	pPriorityList.AddAI(pInDetectionRange, 1)
	pPriorityList.AddAI(pPlayerInScanningRange, 2)
	pPriorityList.AddAI(pInActivationRange, 3)
	pPriorityList.AddAI(pOutpostCheck, 4)
	# Done creating PriorityListAI PriorityList
	#########################################
	return pPriorityList
