import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI Call_TransportsLandingTroops at (308, 188)
	pCall_TransportsLandingTroops = App.PlainAI_Create(pShip, "Call_TransportsLandingTroops")
	pCall_TransportsLandingTroops.SetScriptModule("RunScript")
	pCall_TransportsLandingTroops.SetInterruptable(1)
	pScript = pCall_TransportsLandingTroops.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode6.E6M3.E6M3")
	pScript.SetFunction("TransportsLandingTroops")
	# Done creating PlainAI Call_TransportsLandingTroops
	#########################################
	#########################################
	# Creating ConditionalAI CloseToStation at (313, 260)
	## Conditions:
	#### Condition StationIn8kAway
	pStationIn8kAway = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 45, pShip.GetName(), "Savoy Station")
	## Evaluation function:
	def EvalFunc(bStationIn8kAway):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bStationIn8kAway):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pCloseToStation = App.ConditionalAI_Create(pShip, "CloseToStation")
	pCloseToStation.SetInterruptable(1)
	pCloseToStation.SetContainedAI(pCall_TransportsLandingTroops)
	pCloseToStation.AddCondition(pStationIn8kAway)
	pCloseToStation.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI CloseToStation
	#########################################
	#########################################
	# Creating PlainAI OrbitStation at (420, 148)
	pOrbitStation = App.PlainAI_Create(pShip, "OrbitStation")
	pOrbitStation.SetScriptModule("CircleObject")
	pOrbitStation.SetInterruptable(1)
	pScript = pOrbitStation.GetScriptInstance()
	pScript.SetFollowObjectName("Savoy Station")
	pScript.SetNearFacingVector(App.TGPoint3_GetModelUp())
	pScript.SetRoughDistances(25, 44)
	pScript.SetCircleSpeed(1)
	# Done creating PlainAI OrbitStation
	#########################################
	pOrbitStation.UnregisterExternalFunction("SetTarget", None)
	#########################################
	# Creating PreprocessingAI Fire at (424, 210)
	## Setup:
	import AI.Preprocessors
	pFireScript = AI.Preprocessors.FireScript("player")
	for pSystem in [ pShip.GetTorpedoSystem(), pShip.GetPhaserSystem(), pShip.GetPulseWeaponSystem() ]:
		if not App.IsNull(pSystem):
			pFireScript.AddWeaponSystem( pSystem )
	## The PreprocessingAI:
	pFire = App.PreprocessingAI_Create(pShip, "Fire")
	pFire.SetInterruptable(1)
	pFire.SetPreprocessingMethod(pFireScript, "Update")
	pFire.SetContainedAI(pOrbitStation)
	# Done creating PreprocessingAI Fire
	#########################################
	#########################################
	# Creating PreprocessingAI SelectTarget at (423, 270)
	## Setup:
	import AI.Preprocessors
	pAllTargetsGroup = App.ObjectGroup()
	pAllTargetsGroup.AddName("player")
	pAllTargetsGroup.AddName("Khitomer")
	pAllTargetsGroup.AddName("Devore")
	pAllTargetsGroup.AddName("Venture")
	pAllTargetsGroup.AddName("San Francisco")
	pSelectionPreprocess = AI.Preprocessors.SelectTarget(pAllTargetsGroup)
	## The PreprocessingAI:
	pSelectTarget = App.PreprocessingAI_Create(pShip, "SelectTarget")
	pSelectTarget.SetInterruptable(1)
	pSelectTarget.SetPreprocessingMethod(pSelectionPreprocess, "Update")
	pSelectTarget.SetContainedAI(pFire)
	# Done creating PreprocessingAI SelectTarget
	#########################################
	#########################################
	# Creating PlainAI OrbitStation_NoTargets at (464, 337)
	pOrbitStation_NoTargets = App.PlainAI_Create(pShip, "OrbitStation_NoTargets")
	pOrbitStation_NoTargets.SetScriptModule("CircleObject")
	pOrbitStation_NoTargets.SetInterruptable(1)
	pScript = pOrbitStation_NoTargets.GetScriptInstance()
	pScript.SetFollowObjectName("Savoy Station")
	pScript.SetNearFacingVector(App.TGPoint3_GetModelUp())
	pScript.SetRoughDistances(25, 44)
	pScript.SetCircleSpeed(1)
	# Done creating PlainAI OrbitStation_NoTargets
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (223, 353)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (380, 351)
	pPriorityList.AddAI(pCloseToStation, 1)
	pPriorityList.AddAI(pSelectTarget, 2)
	pPriorityList.AddAI(pOrbitStation_NoTargets, 3)
	# Done creating PriorityListAI PriorityList
	#########################################
	return pPriorityList
