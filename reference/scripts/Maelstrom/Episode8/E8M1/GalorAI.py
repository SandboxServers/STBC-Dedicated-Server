import App

def CreateAI(pShip):

	#########################################
	# Creating PlainAI ReturnToDevice at (347, 155)
	pReturnToDevice = App.PlainAI_Create(pShip, "ReturnToDevice")
	pReturnToDevice.SetScriptModule("Intercept")
	pReturnToDevice.SetInterruptable(1)
	pScript = pReturnToDevice.GetScriptInstance()
	pScript.SetTargetObjectName("Device 1")
	# Done creating PlainAI ReturnToDevice
	#########################################
	#########################################
	# Creating ConditionalAI InRangeofDevice at (258, 175)
	## Conditions:
	#### Condition RangeCondition
	pRangeCondition = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 200, "Galor", "Device 1")
	## Evaluation function:
	def EvalFunc(bRangeCondition):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bRangeCondition:
			return DORMANT
		else:
			return ACTIVE
	## The ConditionalAI:
	pInRangeofDevice = App.ConditionalAI_Create(pShip, "InRangeofDevice")
	pInRangeofDevice.SetInterruptable(1)
	pInRangeofDevice.SetContainedAI(pReturnToDevice)
	pInRangeofDevice.AddCondition(pRangeCondition)
	pInRangeofDevice.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI InRangeofDevice
	#########################################
	#########################################
	# Creating CompoundAI Attack at (359, 100)
	import AI.Compound.BasicAttack
	pAttack = AI.Compound.BasicAttack.CreateAI(pShip, "player", "USS Geronimo", "USS San Francisco")
	# Done creating CompoundAI Attack
	#########################################
	#########################################
	# Creating ConditionalAI InRangeofPlayer at (273, 120)
	## Conditions:
	#### Condition RangeCondition
	pRangeCondition = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 450, pShip.GetName(), "player", "USS Geronimo", "U.S.S San Francisco")
	## Evaluation function:
	def EvalFunc(bRangeCondition):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bRangeCondition:
			return ACTIVE
		else:
			return DORMANT
	## The ConditionalAI:
	pInRangeofPlayer = App.ConditionalAI_Create(pShip, "InRangeofPlayer")
	pInRangeofPlayer.SetInterruptable(1)
	pInRangeofPlayer.SetContainedAI(pAttack)
	pInRangeofPlayer.AddCondition(pRangeCondition)
	pInRangeofPlayer.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI InRangeofPlayer
	#########################################
	#########################################
	# Creating PlainAI TurnTowards at (311, 65)
	pTurnTowards = App.PlainAI_Create(pShip, "TurnTowards")
	pTurnTowards.SetScriptModule("TurnToOrientation")
	pTurnTowards.SetInterruptable(1)
	pScript = pTurnTowards.GetScriptInstance()
	pScript.SetObjectName("player")
	# Done creating PlainAI TurnTowards
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (155, 64)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (249, 71)
	pPriorityList.AddAI(pInRangeofDevice, 1)
	pPriorityList.AddAI(pInRangeofPlayer, 2)
	pPriorityList.AddAI(pTurnTowards, 3)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (66, 84)
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
