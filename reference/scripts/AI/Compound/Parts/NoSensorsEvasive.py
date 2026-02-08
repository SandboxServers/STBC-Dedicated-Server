import App

def CreateAI(pShip):
	#########################################
	# Creating PlainAI DriftUp at (111, 32)
	pDriftUp = App.PlainAI_Create(pShip, "DriftUp")
	pDriftUp.SetScriptModule("ManeuverLoop")
	pDriftUp.SetInterruptable(1)
	pScript = pDriftUp.GetScriptInstance()
	pScript.SetLoopFraction(0.15)
	pScript.SetTurnAxis(App.TGPoint3_GetModelLeft())
	# Done creating PlainAI DriftUp
	#########################################
	#########################################
	# Creating PlainAI DriftDown at (207, 32)
	pDriftDown = App.PlainAI_Create(pShip, "DriftDown")
	pDriftDown.SetScriptModule("ManeuverLoop")
	pDriftDown.SetInterruptable(1)
	pScript = pDriftDown.GetScriptInstance()
	pScript.SetLoopFraction(0.15)
	pScript.SetTurnAxis(App.TGPoint3_GetModelRight())
	# Done creating PlainAI DriftDown
	#########################################
	#########################################
	# Creating PlainAI DriftRight at (302, 32)
	pDriftRight = App.PlainAI_Create(pShip, "DriftRight")
	pDriftRight.SetScriptModule("ManeuverLoop")
	pDriftRight.SetInterruptable(1)
	pScript = pDriftRight.GetScriptInstance()
	pScript.SetLoopFraction(0.15)
	pScript.SetTurnAxis(App.TGPoint3_GetModelUp())
	# Done creating PlainAI DriftRight
	#########################################
	#########################################
	# Creating PlainAI DriftLeft at (396, 32)
	pDriftLeft = App.PlainAI_Create(pShip, "DriftLeft")
	pDriftLeft.SetScriptModule("ManeuverLoop")
	pDriftLeft.SetInterruptable(1)
	pScript = pDriftLeft.GetScriptInstance()
	pScript.SetLoopFraction(0.15)
	pScript.SetTurnAxis(App.TGPoint3_GetModelDown())
	# Done creating PlainAI DriftLeft
	#########################################
	#########################################
	# Creating RandomAI Random at (111, 165)
	pRandom = App.RandomAI_Create(pShip, "Random")
	pRandom.SetInterruptable(1)
	# SeqBlock is at (214, 172)
	pRandom.AddAI(pDriftUp)
	pRandom.AddAI(pDriftDown)
	pRandom.AddAI(pDriftRight)
	pRandom.AddAI(pDriftLeft)
	# Done creating RandomAI Random
	#########################################
	#########################################
	# Creating SequenceAI LoopForever at (38, 216)
	pLoopForever = App.SequenceAI_Create(pShip, "LoopForever")
	pLoopForever.SetInterruptable(1)
	pLoopForever.SetLoopCount(-1)
	pLoopForever.SetResetIfInterrupted(1)
	pLoopForever.SetDoubleCheckAllDone(1)
	pLoopForever.SetSkipDormant(0)
	# SeqBlock is at (145, 219)
	pLoopForever.AddAI(pRandom)
	# Done creating SequenceAI LoopForever
	#########################################
	#########################################
	# Creating ConditionalAI SensorsDisabled at (36, 267)
	## Conditions:
	#### Condition Disabled
	pDisabled = App.ConditionScript_Create("Conditions.ConditionSystemDisabled", "ConditionSystemDisabled", pShip.GetName(), App.CT_SENSOR_SUBSYSTEM)
	## Evaluation function:
	def EvalFunc(bDisabled):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bDisabled:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pSensorsDisabled = App.ConditionalAI_Create(pShip, "SensorsDisabled")
	pSensorsDisabled.SetInterruptable(1)
	pSensorsDisabled.SetContainedAI(pLoopForever)
	pSensorsDisabled.AddCondition(pDisabled)
	pSensorsDisabled.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI SensorsDisabled
	#########################################
	return pSensorsDisabled
