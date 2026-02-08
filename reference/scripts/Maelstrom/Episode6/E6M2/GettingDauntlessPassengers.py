import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI OrbitDauntless at (152, 46)
	pOrbitDauntless = App.PlainAI_Create(pShip, "OrbitDauntless")
	pOrbitDauntless.SetScriptModule("CircleObject")
	pOrbitDauntless.SetInterruptable(1)
	pScript = pOrbitDauntless.GetScriptInstance()
	pScript.SetFollowObjectName("Dauntless")
	pScript.SetNearFacingVector(App.TGPoint3_GetModelUp())
	pScript.SetRoughDistances(10, 12)
	pScript.SetCircleSpeed(0.2)
	# Done creating PlainAI OrbitDauntless
	#########################################
	#########################################
	# Creating ConditionalAI TimeNotPassed at (155, 97)
	## Conditions:
	#### Condition TimePassed
	pTimePassed = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 5.0)
	## Evaluation function:
	def EvalFunc(bTimePassed):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bTimePassed:
			return DONE
		return ACTIVE
	## The ConditionalAI:
	pTimeNotPassed = App.ConditionalAI_Create(pShip, "TimeNotPassed")
	pTimeNotPassed.SetInterruptable(1)
	pTimeNotPassed.SetContainedAI(pOrbitDauntless)
	pTimeNotPassed.AddCondition(pTimePassed)
	pTimeNotPassed.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI TimeNotPassed
	#########################################
	#########################################
	# Creating PlainAI PeriodicCheck at (262, 104)
	pPeriodicCheck = App.PlainAI_Create(pShip, "PeriodicCheck")
	pPeriodicCheck.SetScriptModule("RunScript")
	pPeriodicCheck.SetInterruptable(1)
	pScript = pPeriodicCheck.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode6.E6M2.E6M2")
	pScript.SetFunction("NightFiveSecondsAtDauntless")
	# Done creating PlainAI PeriodicCheck
	#########################################
	#########################################
	# Creating SequenceAI Sequence_2 at (123, 175)
	pSequence_2 = App.SequenceAI_Create(pShip, "Sequence_2")
	pSequence_2.SetInterruptable(1)
	pSequence_2.SetLoopCount(-1)
	pSequence_2.SetResetIfInterrupted(1)
	pSequence_2.SetDoubleCheckAllDone(1)
	pSequence_2.SetSkipDormant(0)
	# SeqBlock is at (230, 164)
	pSequence_2.AddAI(pTimeNotPassed)
	pSequence_2.AddAI(pPeriodicCheck)
	# Done creating SequenceAI Sequence_2
	#########################################
	#########################################
	# Creating PreprocessingAI SetGreenAlert at (122, 230)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AlertLevel(App.ShipClass.GREEN_ALERT)
	## The PreprocessingAI:
	pSetGreenAlert = App.PreprocessingAI_Create(pShip, "SetGreenAlert")
	pSetGreenAlert.SetInterruptable(1)
	pSetGreenAlert.SetPreprocessingMethod(pScript, "Update")
	pSetGreenAlert.SetContainedAI(pSequence_2)
	# Done creating PreprocessingAI SetGreenAlert
	#########################################
	#########################################
	# Creating ConditionalAI NotAttackedByGalors at (120, 283)
	## Conditions:
	#### Condition AttackedKeldon1
	pAttackedKeldon1 = App.ConditionScript_Create("Conditions.ConditionAttackedBy", "ConditionAttackedBy", pShip.GetName(), "Keldon 1", 0.01, 0.01, 99)
	#### Condition AttackedGalor2
	pAttackedGalor2 = App.ConditionScript_Create("Conditions.ConditionAttackedBy", "ConditionAttackedBy", pShip.GetName(), "Galor 2", 0.01, 0.01, 99)
	## Evaluation function:
	def EvalFunc(bAttackedKeldon1, bAttackedGalor2):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bAttackedKeldon1 or bAttackedGalor2):
			return DONE
		return ACTIVE
	## The ConditionalAI:
	pNotAttackedByGalors = App.ConditionalAI_Create(pShip, "NotAttackedByGalors")
	pNotAttackedByGalors.SetInterruptable(1)
	pNotAttackedByGalors.SetContainedAI(pSetGreenAlert)
	pNotAttackedByGalors.AddCondition(pAttackedKeldon1)
	pNotAttackedByGalors.AddCondition(pAttackedGalor2)
	pNotAttackedByGalors.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI NotAttackedByGalors
	#########################################
	#########################################
	# Creating PlainAI Call_NightUnderFire at (213, 235)
	pCall_NightUnderFire = App.PlainAI_Create(pShip, "Call_NightUnderFire")
	pCall_NightUnderFire.SetScriptModule("RunScript")
	pCall_NightUnderFire.SetInterruptable(1)
	pScript = pCall_NightUnderFire.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode6.E6M2.E6M2")
	pScript.SetFunction("NightUnderFire")
	# Done creating PlainAI Call_NightUnderFire
	#########################################
	#########################################
	# Creating PlainAI Call_NightTakingDamage at (374, 72)
	pCall_NightTakingDamage = App.PlainAI_Create(pShip, "Call_NightTakingDamage")
	pCall_NightTakingDamage.SetScriptModule("RunScript")
	pCall_NightTakingDamage.SetInterruptable(1)
	pScript = pCall_NightTakingDamage.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode6.E6M2.E6M2")
	pScript.SetFunction("NightTakingDamage")
	# Done creating PlainAI Call_NightTakingDamage
	#########################################
	#########################################
	# Creating ConditionalAI HullTakingDamage at (377, 127)
	## Conditions:
	#### Condition HullAt60
	pHullAt60 = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName(), App.CT_HULL_SUBSYSTEM, 0.60)
	## Evaluation function:
	def EvalFunc(bHullAt60):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bHullAt60):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pHullTakingDamage = App.ConditionalAI_Create(pShip, "HullTakingDamage")
	pHullTakingDamage.SetInterruptable(1)
	pHullTakingDamage.SetContainedAI(pCall_NightTakingDamage)
	pHullTakingDamage.AddCondition(pHullAt60)
	pHullTakingDamage.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI HullTakingDamage
	#########################################
	#########################################
	# Creating PlainAI OrbitDauntless_2 at (486, 123)
	pOrbitDauntless_2 = App.PlainAI_Create(pShip, "OrbitDauntless_2")
	pOrbitDauntless_2.SetScriptModule("CircleObject")
	pOrbitDauntless_2.SetInterruptable(1)
	pScript = pOrbitDauntless_2.GetScriptInstance()
	pScript.SetFollowObjectName("Dauntless")
	pScript.SetNearFacingVector(App.TGPoint3_GetModelUp())
	pScript.SetRoughDistances(10, 12)
	pScript.SetCircleSpeed(0.2)
	# Done creating PlainAI OrbitDauntless_2
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (310, 186)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (409, 193)
	pPriorityList.AddAI(pHullTakingDamage, 1)
	pPriorityList.AddAI(pOrbitDauntless_2, 2)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PreprocessingAI RedAlert at (310, 234)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AlertLevel(App.ShipClass.RED_ALERT)
	## The PreprocessingAI:
	pRedAlert = App.PreprocessingAI_Create(pShip, "RedAlert")
	pRedAlert.SetInterruptable(1)
	pRedAlert.SetPreprocessingMethod(pScript, "Update")
	pRedAlert.SetContainedAI(pPriorityList)
	# Done creating PreprocessingAI RedAlert
	#########################################
	#########################################
	# Creating ConditionalAI TimeNotPassed_2 at (310, 283)
	## Conditions:
	#### Condition TimePassed
	pTimePassed = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 20.0, 1)
	## Evaluation function:
	def EvalFunc(bTimePassed):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bTimePassed:
			return DONE
		return ACTIVE
	## The ConditionalAI:
	pTimeNotPassed_2 = App.ConditionalAI_Create(pShip, "TimeNotPassed_2")
	pTimeNotPassed_2.SetInterruptable(1)
	pTimeNotPassed_2.SetContainedAI(pRedAlert)
	pTimeNotPassed_2.AddCondition(pTimePassed)
	pTimeNotPassed_2.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI TimeNotPassed_2
	#########################################
	#########################################
	# Creating SequenceAI Sequence at (41, 332)
	pSequence = App.SequenceAI_Create(pShip, "Sequence")
	pSequence.SetInterruptable(1)
	pSequence.SetLoopCount(-1)
	pSequence.SetResetIfInterrupted(1)
	pSequence.SetDoubleCheckAllDone(0)
	pSequence.SetSkipDormant(0)
	# SeqBlock is at (191, 340)
	pSequence.AddAI(pNotAttackedByGalors)
	pSequence.AddAI(pCall_NightUnderFire)
	pSequence.AddAI(pTimeNotPassed_2)
	# Done creating SequenceAI Sequence
	#########################################
	return pSequence
