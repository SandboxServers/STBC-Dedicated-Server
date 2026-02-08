import App

def CreateAI(pShip):
	#########################################
	# Creating PlainAI OutpostDisabledFunc at (344, 319)
	pOutpostDisabledFunc = App.PlainAI_Create(pShip, "OutpostDisabledFunc")
	pOutpostDisabledFunc.SetScriptModule("RunScript")
	pOutpostDisabledFunc.SetInterruptable(1)
	pScript = pOutpostDisabledFunc.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode5.E5M2.E5M2")
	pScript.SetFunction("OutpostPhasersOut")
	# Done creating PlainAI OutpostDisabledFunc
	#########################################
	#########################################
	# Creating PlainAI Stay at (345, 351)
	pStay = App.PlainAI_Create(pShip, "Stay")
	pStay.SetScriptModule("Stay")
	pStay.SetInterruptable(1)
	# Done creating PlainAI Stay
	#########################################
	#########################################
	# Creating SequenceAI Sequence_2 at (342, 270)
	pSequence_2 = App.SequenceAI_Create(pShip, "Sequence_2")
	pSequence_2.SetInterruptable(1)
	pSequence_2.SetLoopCount(1)
	pSequence_2.SetResetIfInterrupted(1)
	pSequence_2.SetDoubleCheckAllDone(0)
	pSequence_2.SetSkipDormant(0)
	# SeqBlock is at (344, 301)
	pSequence_2.AddAI(pOutpostDisabledFunc)
	pSequence_2.AddAI(pStay)
	# Done creating SequenceAI Sequence_2
	#########################################
	#########################################
	# Creating ConditionalAI OutpostCheck at (342, 238)
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
	# Creating CompoundAI OutpostAttack at (435, 228)
	import AI.Compound.StarbaseAttack
	pOutpostAttack = AI.Compound.StarbaseAttack.CreateAI(pShip, "player")
	# Done creating CompoundAI OutpostAttack
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList_2 at (256, 167)
	pPriorityList_2 = App.PriorityListAI_Create(pShip, "PriorityList_2")
	pPriorityList_2.SetInterruptable(1)
	# SeqBlock is at (394, 208)
	pPriorityList_2.AddAI(pOutpostCheck, 1)
	pPriorityList_2.AddAI(pOutpostAttack, 2)
	# Done creating PriorityListAI PriorityList_2
	#########################################
	return pPriorityList_2
