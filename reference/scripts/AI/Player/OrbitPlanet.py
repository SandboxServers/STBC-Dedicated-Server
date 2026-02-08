import App

def StartingOrbit(pShip, pPlanet):
	# Send an event saying that the ship is now orbitting the
	# planet it's around.
	pEvent = App.TGEvent_Create()
	pEvent.SetEventType(App.ET_AI_ORBITTING)
	pEvent.SetDestination(pPlanet)
	pEvent.SetSource(pShip)
	App.g_kEventManager.AddEvent(pEvent)

def CreateAI(pShip, pPlanet):
	#########################################
	# Creating PlainAI StartingOrbitScript at (241, 52)
	pStartingOrbitScript = App.PlainAI_Create(pShip, "StartingOrbitScript")
	pStartingOrbitScript.SetScriptModule("RunScript")
	pStartingOrbitScript.SetInterruptable(1)
	pScript = pStartingOrbitScript.GetScriptInstance()
	pScript.SetScriptModule(__name__)
	pScript.SetFunction("StartingOrbit")
	pScript.SetArguments(pShip, pPlanet)
	# Done creating PlainAI StartingOrbitScript
	#########################################
	#########################################
	# Creating PlainAI CirclePlanet at (353, 55)
	pCirclePlanet = App.PlainAI_Create(pShip, "CirclePlanet")
	pCirclePlanet.SetScriptModule("CircleObject")
	pCirclePlanet.SetInterruptable(1)
	pScript = pCirclePlanet.GetScriptInstance()
	pScript.SetFollowObjectName(pPlanet.GetName())
	pScript.SetNearFacingVector(App.TGPoint3_GetModelLeft())
	pScript.SetRoughDistances(pPlanet.GetRadius() + 150, pPlanet.GetRadius() + 190)
	# Done creating PlainAI CirclePlanet
	#########################################
	#########################################
	# Creating SequenceAI Sequence at (201, 111)
	pSequence = App.SequenceAI_Create(pShip, "Sequence")
	pSequence.SetInterruptable(1)
	pSequence.SetLoopCount(1)
	pSequence.SetResetIfInterrupted(1)
	pSequence.SetDoubleCheckAllDone(0)
	pSequence.SetSkipDormant(0)
	# SeqBlock is at (301, 127)
	pSequence.AddAI(pStartingOrbitScript)
	pSequence.AddAI(pCirclePlanet)
	# Done creating SequenceAI Sequence
	#########################################
	#########################################
	# Creating ConditionalAI CloseEnough at (210, 167)
	## Conditions:
	#### Condition InRange
	pInRange = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 200.0 + pPlanet.GetRadius(),  pShip.GetName(), pPlanet.GetName())
	## Evaluation function:
	def EvalFunc(bInRange):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bInRange:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pCloseEnough = App.ConditionalAI_Create(pShip, "CloseEnough")
	pCloseEnough.SetInterruptable(1)
	pCloseEnough.SetContainedAI(pSequence)
	pCloseEnough.AddCondition(pInRange)
	pCloseEnough.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI CloseEnough
	#########################################
	#########################################
	# Creating PlainAI FlyToPlanet at (328, 183)
	pFlyToPlanet = App.PlainAI_Create(pShip, "FlyToPlanet")
	pFlyToPlanet.SetScriptModule("Intercept")
	pFlyToPlanet.SetInterruptable(1)
	pScript = pFlyToPlanet.GetScriptInstance()
	pScript.SetTargetObjectName(pPlanet.GetName())
	pScript.SetInterceptDistance(0.0)
	pScript.SetAddObjectRadius(1)
	# Done creating PlainAI FlyToPlanet
	#########################################
	#########################################
	# Creating PriorityListAI OrbitPriorityList at (156, 227)
	pOrbitPriorityList = App.PriorityListAI_Create(pShip, "OrbitPriorityList")
	pOrbitPriorityList.SetInterruptable(1)
	# SeqBlock is at (272, 228)
	pOrbitPriorityList.AddAI(pCloseEnough, 1)
	pOrbitPriorityList.AddAI(pFlyToPlanet, 2)
	# Done creating PriorityListAI OrbitPriorityList
	#########################################
	#########################################
	# Creating PreprocessingAI OrbitAvoidObstacles at (128, 289)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pOrbitAvoidObstacles = App.PreprocessingAI_Create(pShip, "OrbitAvoidObstacles")
	pOrbitAvoidObstacles.SetInterruptable(1)
	pOrbitAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pOrbitAvoidObstacles.SetContainedAI(pOrbitPriorityList)
	# Done creating PreprocessingAI OrbitAvoidObstacles
	#########################################
	return pOrbitAvoidObstacles
