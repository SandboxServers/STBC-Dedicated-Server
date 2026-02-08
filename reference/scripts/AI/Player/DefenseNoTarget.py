import App

def CreateAI(pShip):
	#########################################
	# Creating PlainAI EvadeTorps at (109, 128)
	pEvadeTorps = App.PlainAI_Create(pShip, "EvadeTorps")
	pEvadeTorps.SetScriptModule("EvadeTorps")
	pEvadeTorps.SetInterruptable(1)
	# Done creating PlainAI EvadeTorps
	#########################################
	#########################################
	# Creating ConditionalAI IncomingTorps at (109, 186)
	## Conditions:
	#### Condition Incoming
	pIncoming = App.ConditionScript_Create("Conditions.ConditionIncomingTorps", "ConditionIncomingTorps", pShip.GetName())
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
	pIncomingTorps.SetContainedAI(pEvadeTorps)
	pIncomingTorps.AddCondition(pIncoming)
	pIncomingTorps.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI IncomingTorps
	#########################################
	#########################################
	# Creating PlainAI Maneuver at (179, 30)
	pManeuver = App.PlainAI_Create(pShip, "Maneuver")
	pManeuver.SetScriptModule("ManeuverLoop")
	pManeuver.SetInterruptable(1)
	pScript = pManeuver.GetScriptInstance()
	pScript.SetLoopFraction(0.5)
	pScript.SetTurnAxis(App.TGPoint3_GetModelLeft())
	# Done creating PlainAI Maneuver
	#########################################
	#########################################
	# Creating PlainAI Maneuver_2 at (268, 30)
	pManeuver_2 = App.PlainAI_Create(pShip, "Maneuver_2")
	pManeuver_2.SetScriptModule("ManeuverLoop")
	pManeuver_2.SetInterruptable(1)
	pScript = pManeuver_2.GetScriptInstance()
	pScript.SetLoopFraction(0.5)
	pScript.SetTurnAxis(App.TGPoint3_GetModelRight())
	# Done creating PlainAI Maneuver_2
	#########################################
	#########################################
	# Creating PlainAI Maneuver_3 at (361, 29)
	pManeuver_3 = App.PlainAI_Create(pShip, "Maneuver_3")
	pManeuver_3.SetScriptModule("ManeuverLoop")
	pManeuver_3.SetInterruptable(1)
	pScript = pManeuver_3.GetScriptInstance()
	pScript.SetLoopFraction(0.5)
	pScript.SetTurnAxis(App.TGPoint3_GetModelUp())
	# Done creating PlainAI Maneuver_3
	#########################################
	#########################################
	# Creating PlainAI Maneuver_4 at (452, 29)
	pManeuver_4 = App.PlainAI_Create(pShip, "Maneuver_4")
	pManeuver_4.SetScriptModule("ManeuverLoop")
	pManeuver_4.SetInterruptable(1)
	pScript = pManeuver_4.GetScriptInstance()
	pScript.SetLoopFraction(0.5)
	pScript.SetTurnAxis(App.TGPoint3_GetModelDown())
	# Done creating PlainAI Maneuver_4
	#########################################
	#########################################
	# Creating PlainAI Maneuver_5 at (542, 29)
	pManeuver_5 = App.PlainAI_Create(pShip, "Maneuver_5")
	pManeuver_5.SetScriptModule("ManeuverLoop")
	pManeuver_5.SetInterruptable(1)
	pScript = pManeuver_5.GetScriptInstance()
	pScript.SetLoopFraction(0.25)
	pScript.SetTurnAxis(App.TGPoint3_GetModelForward())
	# Done creating PlainAI Maneuver_5
	#########################################
	#########################################
	# Creating PlainAI Maneuver_6 at (546, 71)
	pManeuver_6 = App.PlainAI_Create(pShip, "Maneuver_6")
	pManeuver_6.SetScriptModule("ManeuverLoop")
	pManeuver_6.SetInterruptable(1)
	pScript = pManeuver_6.GetScriptInstance()
	pScript.SetLoopFraction(0.25)
	pScript.SetTurnAxis(App.TGPoint3_GetModelBackward())
	# Done creating PlainAI Maneuver_6
	#########################################
	#########################################
	# Creating PlainAI Maneuver_7 at (547, 122)
	pManeuver_7 = App.PlainAI_Create(pShip, "Maneuver_7")
	pManeuver_7.SetScriptModule("ManeuverLoop")
	pManeuver_7.SetInterruptable(1)
	pScript = pManeuver_7.GetScriptInstance()
	pScript.SetLoopFraction(0.5)
	pScript.SetTurnAxis(App.TGPoint3_GetModelUp())
	pScript.SetSpeeds(fStartSpeed = 1.0, fEndSpeed = 0)
	# Done creating PlainAI Maneuver_7
	#########################################
	#########################################
	# Creating RandomAI RandomManeuver at (301, 184)
	pRandomManeuver = App.RandomAI_Create(pShip, "RandomManeuver")
	pRandomManeuver.SetInterruptable(1)
	# SeqBlock is at (403, 189)
	pRandomManeuver.AddAI(pManeuver)
	pRandomManeuver.AddAI(pManeuver_2)
	pRandomManeuver.AddAI(pManeuver_3)
	pRandomManeuver.AddAI(pManeuver_4)
	pRandomManeuver.AddAI(pManeuver_5)
	pRandomManeuver.AddAI(pManeuver_6)
	pRandomManeuver.AddAI(pManeuver_7)
	# Done creating RandomAI RandomManeuver
	#########################################
	#########################################
	# Creating SequenceAI FlyAround at (212, 229)
	pFlyAround = App.SequenceAI_Create(pShip, "FlyAround")
	pFlyAround.SetInterruptable(1)
	pFlyAround.SetLoopCount(-1)
	pFlyAround.SetResetIfInterrupted(1)
	pFlyAround.SetDoubleCheckAllDone(1)
	pFlyAround.SetSkipDormant(0)
	# SeqBlock is at (311, 235)
	pFlyAround.AddAI(pRandomManeuver)
	# Done creating SequenceAI FlyAround
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (82, 274)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (196, 279)
	pPriorityList.AddAI(pIncomingTorps, 1)
	pPriorityList.AddAI(pFlyAround, 2)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (44, 319)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pPriorityList)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
