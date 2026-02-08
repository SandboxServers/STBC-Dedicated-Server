import App

def CreateAI(pShip, fInterceptSpeed):


	#########################################
	# Creating PlainAI FlyToWayPoint at (37, 110)
	pFlyToWayPoint = App.PlainAI_Create(pShip, "FlyToWayPoint")
	pFlyToWayPoint.SetScriptModule("Intercept")
	pFlyToWayPoint.SetInterruptable(1)
	pScript = pFlyToWayPoint.GetScriptInstance()
	pScript.SetTargetObjectName("MarauderWarp")
	pScript.SetMaximumSpeed(2)
	pScript.SetInSystemWarpDistance(10000)
	# Done creating PlainAI FlyToWayPoint
	#########################################
	#########################################
	# Creating PreprocessingAI GreenAlert at (38, 154)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AlertLevel(App.ShipClass.GREEN_ALERT)
	## The PreprocessingAI:
	pGreenAlert = App.PreprocessingAI_Create(pShip, "GreenAlert")
	pGreenAlert.SetInterruptable(1)
	pGreenAlert.SetPreprocessingMethod(pScript, "Update")
	pGreenAlert.SetContainedAI(pFlyToWayPoint)
	# Done creating PreprocessingAI GreenAlert
	#########################################
	#########################################
	# Creating ConditionalAI PlayerNotClose at (38, 197)
	## Conditions:
	#### Condition PlayerInRange
	pPlayerInRange = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 800, pShip.GetName(), "player")
	## Evaluation function:
	def EvalFunc(bPlayerInRange):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bPlayerInRange:
			return DONE
		return ACTIVE
	## The ConditionalAI:
	pPlayerNotClose = App.ConditionalAI_Create(pShip, "PlayerNotClose")
	pPlayerNotClose.SetInterruptable(1)
	pPlayerNotClose.SetContainedAI(pGreenAlert)
	pPlayerNotClose.AddCondition(pPlayerInRange)
	pPlayerNotClose.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI PlayerNotClose
	#########################################
	#########################################
	# Creating PlainAI Call_MarauderRuns at (133, 33)
	pCall_MarauderRuns = App.PlainAI_Create(pShip, "Call_MarauderRuns")
	pCall_MarauderRuns.SetScriptModule("RunScript")
	pCall_MarauderRuns.SetInterruptable(1)
	pScript = pCall_MarauderRuns.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode2.E2M2.E2M2")
	pScript.SetFunction("MarauderRuns")
	# Done creating PlainAI Call_MarauderRuns
	#########################################
	#########################################
	# Creating PreprocessingAI RedAlert at (136, 76)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AlertLevel(App.ShipClass.RED_ALERT)
	## The PreprocessingAI:
	pRedAlert = App.PreprocessingAI_Create(pShip, "RedAlert")
	pRedAlert.SetInterruptable(1)
	pRedAlert.SetPreprocessingMethod(pScript, "Update")
	pRedAlert.SetContainedAI(pCall_MarauderRuns)
	# Done creating PreprocessingAI RedAlert
	#########################################
	#########################################
	# Creating PlainAI RunAway at (186, 111)
	pRunAway = App.PlainAI_Create(pShip, "RunAway")
	pRunAway.SetScriptModule("Flee")
	pRunAway.SetInterruptable(1)
	pScript = pRunAway.GetScriptInstance()
	pScript.SetFleeFromGroup("player")
	pScript.SetSpeed(fInterceptSpeed)
	# Done creating PlainAI RunAway
	#########################################
	#########################################
	# Creating ConditionalAI AttackedByPlayer at (187, 154)
	## Conditions:
	#### Condition HitByPlayer
	pHitByPlayer = App.ConditionScript_Create("Conditions.ConditionAttacked", "ConditionAttacked", pShip.GetName(), 0.01, 0.01, 100)
	## Evaluation function:
	def EvalFunc(bHitByPlayer):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bHitByPlayer:
			return DONE
		return ACTIVE
	## The ConditionalAI:
	pAttackedByPlayer = App.ConditionalAI_Create(pShip, "AttackedByPlayer")
	pAttackedByPlayer.SetInterruptable(1)
	pAttackedByPlayer.SetContainedAI(pRunAway)
	pAttackedByPlayer.AddCondition(pHitByPlayer)
	pAttackedByPlayer.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI AttackedByPlayer
	#########################################
	#########################################
	# Creating PlainAI Call_BoostMarauderEngines at (214, 200)
	pCall_BoostMarauderEngines = App.PlainAI_Create(pShip, "Call_BoostMarauderEngines")
	pCall_BoostMarauderEngines.SetScriptModule("RunScript")
	pCall_BoostMarauderEngines.SetInterruptable(1)
	pScript = pCall_BoostMarauderEngines.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode2.E2M2.E2M2")
	pScript.SetFunction("BoostMarauderEngines")
	# Done creating PlainAI Call_BoostMarauderEngines
	#########################################
	#########################################
	# Creating PlainAI RunAway_2 at (307, 72)
	pRunAway_2 = App.PlainAI_Create(pShip, "RunAway_2")
	pRunAway_2.SetScriptModule("Flee")
	pRunAway_2.SetInterruptable(1)
	pScript = pRunAway_2.GetScriptInstance()
	pScript.SetFleeFromGroup("player")
	pScript.SetSpeed(fInterceptSpeed)
	# Done creating PlainAI RunAway_2
	#########################################
	#########################################
	# Creating PreprocessingAI Fire at (313, 128)
	## Setup:
	import AI.Preprocessors
	pFireScript = AI.Preprocessors.FireScript("player")
	for pSystem in [ pShip.GetTorpedoSystem(), pShip.GetPhaserSystem(), pShip.GetPulseWeaponSystem() ]:
		if pSystem:
			pFireScript.AddWeaponSystem( pSystem )
	## The PreprocessingAI:
	pFire = App.PreprocessingAI_Create(pShip, "Fire")
	pFire.SetInterruptable(1)
	pFire.SetPreprocessingMethod(pFireScript, "Update")
	pFire.SetContainedAI(pRunAway_2)
	# Done creating PreprocessingAI Fire
	#########################################
	#########################################
	# Creating PreprocessingAI RedAlert_2 at (313, 170)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AlertLevel(App.ShipClass.RED_ALERT)
	## The PreprocessingAI:
	pRedAlert_2 = App.PreprocessingAI_Create(pShip, "RedAlert_2")
	pRedAlert_2.SetInterruptable(1)
	pRedAlert_2.SetPreprocessingMethod(pScript, "Update")
	pRedAlert_2.SetContainedAI(pFire)
	# Done creating PreprocessingAI RedAlert_2
	#########################################
	#########################################
	# Creating PlainAI StayPut at (415, 181)
	pStayPut = App.PlainAI_Create(pShip, "StayPut")
	pStayPut.SetScriptModule("Stay")
	pStayPut.SetInterruptable(1)
	# Done creating PlainAI StayPut
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (252, 239)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (353, 229)
	pPriorityList.AddAI(pRedAlert_2, 1)
	pPriorityList.AddAI(pStayPut, 2)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating ConditionalAI WarpEnginesNotDisabled at (302, 287)
	## Conditions:
	#### Condition WarpDisabled
	pWarpDisabled = App.ConditionScript_Create("Conditions.ConditionSystemDisabled", "ConditionSystemDisabled", pShip.GetName(),  App.CT_WARP_ENGINE_SUBSYSTEM, 1)
	## Evaluation function:
	def EvalFunc(bWarpDisabled):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bWarpDisabled:
			return DONE
		return ACTIVE
	## The ConditionalAI:
	pWarpEnginesNotDisabled = App.ConditionalAI_Create(pShip, "WarpEnginesNotDisabled")
	pWarpEnginesNotDisabled.SetInterruptable(1)
	pWarpEnginesNotDisabled.SetContainedAI(pPriorityList)
	pWarpEnginesNotDisabled.AddCondition(pWarpDisabled)
	pWarpEnginesNotDisabled.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI WarpEnginesNotDisabled
	#########################################
	#########################################
	# Creating PlainAI Call_MarauderDisabled at (296, 327)
	pCall_MarauderDisabled = App.PlainAI_Create(pShip, "Call_MarauderDisabled")
	pCall_MarauderDisabled.SetScriptModule("RunScript")
	pCall_MarauderDisabled.SetInterruptable(1)
	pScript = pCall_MarauderDisabled.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode2.E2M2.E2M2")
	pScript.SetFunction("MarauderDisabled")
	# Done creating PlainAI Call_MarauderDisabled
	#########################################
	#########################################
	# Creating SequenceAI Sequence at (19, 321)
	pSequence = App.SequenceAI_Create(pShip, "Sequence")
	pSequence.SetInterruptable(1)
	pSequence.SetLoopCount(1)
	pSequence.SetResetIfInterrupted(1)
	pSequence.SetDoubleCheckAllDone(0)
	pSequence.SetSkipDormant(0)
	# SeqBlock is at (149, 337)
	pSequence.AddAI(pPlayerNotClose)
	pSequence.AddAI(pRedAlert)
	pSequence.AddAI(pAttackedByPlayer)
	pSequence.AddAI(pCall_BoostMarauderEngines)
	pSequence.AddAI(pWarpEnginesNotDisabled)
	pSequence.AddAI(pCall_MarauderDisabled)
	# Done creating SequenceAI Sequence
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (8, 365)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pSequence)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
