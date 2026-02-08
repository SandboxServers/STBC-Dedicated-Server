import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI InterceptKhitLaunch at (107, 84)
	pInterceptKhitLaunch = App.PlainAI_Create(pShip, "InterceptKhitLaunch")
	pInterceptKhitLaunch.SetScriptModule("Intercept")
	pInterceptKhitLaunch.SetInterruptable(1)
	pScript = pInterceptKhitLaunch.GetScriptInstance()
	pScript.SetTargetObjectName("KhitLaunch0")
	pScript.SetInterceptDistance(fDistance = 30.0)
	pScript.SetInSystemWarpDistance(fDistance = 50.0)
	# Done creating PlainAI InterceptKhitLaunch
	#########################################
	#########################################
	# Creating PlainAI FlyToKhitLaunch at (212, 90)
	pFlyToKhitLaunch = App.PlainAI_Create(pShip, "FlyToKhitLaunch")
	pFlyToKhitLaunch.SetScriptModule("FollowWaypoints")
	pFlyToKhitLaunch.SetInterruptable(1)
	pScript = pFlyToKhitLaunch.GetScriptInstance()
	pScript.SetTargetWaypointName("KhitLaunch1")
	# Done creating PlainAI FlyToKhitLaunch
	#########################################
	#########################################
	# Creating SequenceAI FlyToStation at (49, 232)
	pFlyToStation = App.SequenceAI_Create(pShip, "FlyToStation")
	pFlyToStation.SetInterruptable(1)
	pFlyToStation.SetLoopCount(1)
	pFlyToStation.SetResetIfInterrupted(1)
	pFlyToStation.SetDoubleCheckAllDone(0)
	pFlyToStation.SetSkipDormant(0)
	# SeqBlock is at (148, 187)
	pFlyToStation.AddAI(pInterceptKhitLaunch)
	pFlyToStation.AddAI(pFlyToKhitLaunch)
	# Done creating SequenceAI FlyToStation
	#########################################
	#########################################
	# Creating PlainAI Call_KhitomerLaunchesShuttles at (204, 188)
	pCall_KhitomerLaunchesShuttles = App.PlainAI_Create(pShip, "Call_KhitomerLaunchesShuttles")
	pCall_KhitomerLaunchesShuttles.SetScriptModule("RunScript")
	pCall_KhitomerLaunchesShuttles.SetInterruptable(1)
	pScript = pCall_KhitomerLaunchesShuttles.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode6.E6M3.E6M3")
	pScript.SetFunction("KhitomerLaunchesShuttles")
	pScript.SetArguments("None")
	# Done creating PlainAI Call_KhitomerLaunchesShuttles
	#########################################
	#########################################
	# Creating ConditionalAI IsPlayerInSavoy1 at (170, 255)
	## Conditions:
	#### Condition PlayerWithKhit
	pPlayerWithKhit = App.ConditionScript_Create("Conditions.ConditionAllInSameSet", "ConditionAllInSameSet", "Khitomer", "player")
	## Evaluation function:
	def EvalFunc(bPlayerWithKhit):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bPlayerWithKhit):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pIsPlayerInSavoy1 = App.ConditionalAI_Create(pShip, "IsPlayerInSavoy1")
	pIsPlayerInSavoy1.SetInterruptable(1)
	pIsPlayerInSavoy1.SetContainedAI(pCall_KhitomerLaunchesShuttles)
	pIsPlayerInSavoy1.AddCondition(pPlayerWithKhit)
	pIsPlayerInSavoy1.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI IsPlayerInSavoy1
	#########################################
	#########################################
	# Creating PlainAI TurnFromStation at (316, 48)
	pTurnFromStation = App.PlainAI_Create(pShip, "TurnFromStation")
	pTurnFromStation.SetScriptModule("Flee")
	pTurnFromStation.SetInterruptable(1)
	pScript = pTurnFromStation.GetScriptInstance()
	pScript.SetFleeFromGroup("Savoy Station")
	pScript.SetSpeed(0)
	# Done creating PlainAI TurnFromStation
	#########################################
	pTurnFromStation.UnregisterExternalFunction("SetTarget", None)
	#########################################
	# Creating PreprocessingAI Fire at (315, 102)
	## Setup:
	import AI.Preprocessors
	pFireScript = AI.Preprocessors.FireScript("Keldon 1")
	for pSystem in [ pShip.GetTorpedoSystem(), pShip.GetPhaserSystem(), pShip.GetPulseWeaponSystem() ]:
		if not App.IsNull(pSystem):
			pFireScript.AddWeaponSystem( pSystem )
	## The PreprocessingAI:
	pFire = App.PreprocessingAI_Create(pShip, "Fire")
	pFire.SetInterruptable(1)
	pFire.SetPreprocessingMethod(pFireScript, "Update")
	pFire.SetContainedAI(pTurnFromStation)
	# Done creating PreprocessingAI Fire
	#########################################
	#########################################
	# Creating PreprocessingAI SelectTarget at (319, 150)
	## Setup:
	import AI.Preprocessors
	pAllTargetsGroup = App.ObjectGroup()
	pAllTargetsGroup.AddName("Keldon 1")
	pAllTargetsGroup.AddName("Galor 3")
	pAllTargetsGroup.AddName("Galor 1")
	pAllTargetsGroup.AddName("Galor 2")
	pAllTargetsGroup.AddName("Keldon 2")
	pAllTargetsGroup.AddName("Transport 1")
	pAllTargetsGroup.AddName("Transport 2")
	pSelectionPreprocess = AI.Preprocessors.SelectTarget(pAllTargetsGroup)
	## The PreprocessingAI:
	pSelectTarget = App.PreprocessingAI_Create(pShip, "SelectTarget")
	pSelectTarget.SetInterruptable(1)
	pSelectTarget.SetPreprocessingMethod(pSelectionPreprocess, "Update")
	pSelectTarget.SetContainedAI(pFire)
	# Done creating PreprocessingAI SelectTarget
	#########################################
	#########################################
	# Creating PlainAI TurnFromStation_2 at (432, 176)
	pTurnFromStation_2 = App.PlainAI_Create(pShip, "TurnFromStation_2")
	pTurnFromStation_2.SetScriptModule("Flee")
	pTurnFromStation_2.SetInterruptable(1)
	pScript = pTurnFromStation_2.GetScriptInstance()
	pScript.SetFleeFromGroup("Savoy Station")
	pScript.SetSpeed(0)
	# Done creating PlainAI TurnFromStation_2
	#########################################
	#########################################
	# Creating PriorityListAI TurnFromStationPriority at (295, 249)
	pTurnFromStationPriority = App.PriorityListAI_Create(pShip, "TurnFromStationPriority")
	pTurnFromStationPriority.SetInterruptable(1)
	# SeqBlock is at (360, 213)
	pTurnFromStationPriority.AddAI(pSelectTarget, 1)
	pTurnFromStationPriority.AddAI(pTurnFromStation_2, 2)
	# Done creating PriorityListAI TurnFromStationPriority
	#########################################
	#########################################
	# Creating SequenceAI Sequence at (27, 328)
	pSequence = App.SequenceAI_Create(pShip, "Sequence")
	pSequence.SetInterruptable(1)
	pSequence.SetLoopCount(1)
	pSequence.SetResetIfInterrupted(1)
	pSequence.SetDoubleCheckAllDone(0)
	pSequence.SetSkipDormant(0)
	# SeqBlock is at (151, 335)
	pSequence.AddAI(pFlyToStation)
	pSequence.AddAI(pIsPlayerInSavoy1)
	pSequence.AddAI(pTurnFromStationPriority)
	# Done creating SequenceAI Sequence
	#########################################
	return pSequence
