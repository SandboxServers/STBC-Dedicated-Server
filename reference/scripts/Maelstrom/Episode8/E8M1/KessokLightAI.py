import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI Run at (516, 97)
	pRun = App.PlainAI_Create(pShip, "Run")
	pRun.SetScriptModule("Flee")
	pRun.SetInterruptable(1)
	pScript = pRun.GetScriptInstance()
	pScript.SetFleeFromGroup("player")
	pScript.SetSpeed(1)
	# Done creating PlainAI Run
	#########################################
	#########################################
	# Creating ConditionalAI Wait at (426, 117)
	## Conditions:
	#### Condition TimePassed
	pTimePassed = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 17, 1)
	## Evaluation function:
	def EvalFunc(bTimePassed):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bTimePassed:
			return DONE
		return ACTIVE
	## The ConditionalAI:
	pWait = App.ConditionalAI_Create(pShip, "Wait")
	pWait.SetInterruptable(1)
	pWait.SetContainedAI(pRun)
	pWait.AddCondition(pTimePassed)
	pWait.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI Wait
	#########################################
	#########################################
	# Creating PlainAI Warp at (465, 59)
	pWarp = App.PlainAI_Create(pShip, "Warp")
	pWarp.SetScriptModule("Warp")
	pWarp.SetInterruptable(1)
	# Done creating PlainAI Warp
	#########################################
	#########################################
	# Creating SequenceAI WaitthenRun at (325, 59)
	pWaitthenRun = App.SequenceAI_Create(pShip, "WaitthenRun")
	pWaitthenRun.SetInterruptable(1)
	pWaitthenRun.SetLoopCount(1)
	pWaitthenRun.SetResetIfInterrupted(1)
	pWaitthenRun.SetDoubleCheckAllDone(0)
	pWaitthenRun.SetSkipDormant(0)
	# SeqBlock is at (417, 66)
	pWaitthenRun.AddAI(pWait)
	pWaitthenRun.AddAI(pWarp)
	# Done creating SequenceAI WaitthenRun
	#########################################
	#########################################
	# Creating ConditionalAI IfDeviceDestroyed at (239, 79)
	## Conditions:
	#### Condition Destroyed
	pDestroyed = App.ConditionScript_Create("Conditions.ConditionDestroyed", "ConditionDestroyed", "Device 2")
	## Evaluation function:
	def EvalFunc(bDestroyed):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if(bDestroyed):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pIfDeviceDestroyed = App.ConditionalAI_Create(pShip, "IfDeviceDestroyed")
	pIfDeviceDestroyed.SetInterruptable(1)
	pIfDeviceDestroyed.SetContainedAI(pWaitthenRun)
	pIfDeviceDestroyed.AddCondition(pDestroyed)
	pIfDeviceDestroyed.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI IfDeviceDestroyed
	#########################################
	#########################################
	# Creating CompoundAI Attack at (273, 26)
	import AI.Compound.BasicAttack
	pAttack = AI.Compound.BasicAttack.CreateAI(pShip, "player", "USS Geronimo", "USS San Francisco", Difficulty = 0.8, UseCloaking = 1)
	# Done creating CompoundAI Attack
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (122, 29)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (229, 36)
	pPriorityList.AddAI(pIfDeviceDestroyed, 1)
	pPriorityList.AddAI(pAttack, 2)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (33, 49)
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
