import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI Run at (305, 246)
	pRun = App.PlainAI_Create(pShip, "Run")
	pRun.SetScriptModule("Flee")
	pRun.SetInterruptable(1)
	pScript = pRun.GetScriptInstance()
	pScript.SetFleeFromGroup("player")
	pScript.SetSpeed(1)
	# Done creating PlainAI Run
	#########################################
	#########################################
	# Creating ConditionalAI Wait at (304, 209)
	## Conditions:
	#### Condition TimePassed
	pTimePassed = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 10, 1)
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
	# Creating PlainAI RunFleeScript at (389, 247)
	pRunFleeScript = App.PlainAI_Create(pShip, "RunFleeScript")
	pRunFleeScript.SetScriptModule("RunScript")
	pRunFleeScript.SetInterruptable(1)
	pScript = pRunFleeScript.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode8.E8M1.E8M1")
	pScript.SetFunction("KessokHeavyFlee")
	# Done creating PlainAI RunFleeScript
	#########################################
	#########################################
	# Creating ConditionalAI Wait_3 at (390, 210)
	## Conditions:
	#### Condition TimePassed
	pTimePassed = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 5, 1)
	## Evaluation function:
	def EvalFunc(bTimePassed):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bTimePassed:
			return DONE
		return ACTIVE
	## The ConditionalAI:
	pWait_3 = App.ConditionalAI_Create(pShip, "Wait_3")
	pWait_3.SetInterruptable(1)
	pWait_3.SetContainedAI(pRunFleeScript)
	pWait_3.AddCondition(pTimePassed)
	pWait_3.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI Wait_3
	#########################################
	#########################################
	# Creating PlainAI WarpOut at (428, 161)
	pWarpOut = App.PlainAI_Create(pShip, "WarpOut")
	pWarpOut.SetScriptModule("Warp")
	pWarpOut.SetInterruptable(1)
	# Done creating PlainAI WarpOut
	#########################################
	#########################################
	# Creating SequenceAI WaitthenRun at (266, 161)
	pWaitthenRun = App.SequenceAI_Create(pShip, "WaitthenRun")
	pWaitthenRun.SetInterruptable(1)
	pWaitthenRun.SetLoopCount(1)
	pWaitthenRun.SetResetIfInterrupted(1)
	pWaitthenRun.SetDoubleCheckAllDone(0)
	pWaitthenRun.SetSkipDormant(0)
	# SeqBlock is at (365, 168)
	pWaitthenRun.AddAI(pWait)
	pWaitthenRun.AddAI(pWait_3)
	pWaitthenRun.AddAI(pWarpOut)
	# Done creating SequenceAI WaitthenRun
	#########################################
	#########################################
	# Creating ConditionalAI ConditionAttacked at (225, 126)
	## Conditions:
	#### Condition WasAttacked
	pWasAttacked = App.ConditionScript_Create("Conditions.ConditionAttacked", "ConditionAttacked", pShip.GetName(), 0, 0, 1)
	## Evaluation function:
	def EvalFunc(bWasAttacked):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bWasAttacked:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pConditionAttacked = App.ConditionalAI_Create(pShip, "ConditionAttacked")
	pConditionAttacked.SetInterruptable(1)
	pConditionAttacked.SetContainedAI(pWaitthenRun)
	pConditionAttacked.AddCondition(pWasAttacked)
	pConditionAttacked.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI ConditionAttacked
	#########################################
	#########################################
	# Creating PlainAI Run_2 at (516, 97)
	pRun_2 = App.PlainAI_Create(pShip, "Run_2")
	pRun_2.SetScriptModule("Flee")
	pRun_2.SetInterruptable(1)
	pScript = pRun_2.GetScriptInstance()
	pScript.SetFleeFromGroup("player")
	pScript.SetSpeed(1)
	# Done creating PlainAI Run_2
	#########################################
	#########################################
	# Creating ConditionalAI Wait_2 at (426, 117)
	## Conditions:
	#### Condition TimePassed
	pTimePassed = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 15, 1)
	## Evaluation function:
	def EvalFunc(bTimePassed):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bTimePassed:
			return DONE
		return ACTIVE
	## The ConditionalAI:
	pWait_2 = App.ConditionalAI_Create(pShip, "Wait_2")
	pWait_2.SetInterruptable(1)
	pWait_2.SetContainedAI(pRun_2)
	pWait_2.AddCondition(pTimePassed)
	pWait_2.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI Wait_2
	#########################################
	#########################################
	# Creating PlainAI Warp at (465, 59)
	pWarp = App.PlainAI_Create(pShip, "Warp")
	pWarp.SetScriptModule("Warp")
	pWarp.SetInterruptable(1)
	# Done creating PlainAI Warp
	#########################################
	#########################################
	# Creating SequenceAI WaitthenRun_2 at (325, 59)
	pWaitthenRun_2 = App.SequenceAI_Create(pShip, "WaitthenRun_2")
	pWaitthenRun_2.SetInterruptable(1)
	pWaitthenRun_2.SetLoopCount(1)
	pWaitthenRun_2.SetResetIfInterrupted(1)
	pWaitthenRun_2.SetDoubleCheckAllDone(0)
	pWaitthenRun_2.SetSkipDormant(0)
	# SeqBlock is at (417, 66)
	pWaitthenRun_2.AddAI(pWait_2)
	pWaitthenRun_2.AddAI(pWarp)
	# Done creating SequenceAI WaitthenRun_2
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
	pIfDeviceDestroyed.SetContainedAI(pWaitthenRun_2)
	pIfDeviceDestroyed.AddCondition(pDestroyed)
	pIfDeviceDestroyed.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI IfDeviceDestroyed
	#########################################
	#########################################
	# Creating PlainAI Stay at (277, 30)
	pStay = App.PlainAI_Create(pShip, "Stay")
	pStay.SetScriptModule("Stay")
	pStay.SetInterruptable(1)
	# Done creating PlainAI Stay
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (122, 29)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (215, 36)
	pPriorityList.AddAI(pConditionAttacked, 1)
	pPriorityList.AddAI(pIfDeviceDestroyed, 2)
	pPriorityList.AddAI(pStay, 3)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (35, 49)
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
