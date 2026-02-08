import App

def CreateAI(pShip, sPlacementName):

	#########################################
	# Creating PlainAI Stay at (386, 172)
	pStay = App.PlainAI_Create(pShip, "Stay")
	pStay.SetScriptModule("Stay")
	pStay.SetInterruptable(1)
	# Done creating PlainAI Stay
	#########################################
	#########################################
	# Creating ConditionalAI Wait at (286, 192)
	## Conditions:
	#### Condition Delay
	pDelay = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 215)
	## Evaluation function:
	def EvalFunc(bDelay):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if(bDelay):
			return DONE
		else:
			return ACTIVE
	## The ConditionalAI:
	pWait = App.ConditionalAI_Create(pShip, "Wait")
	pWait.SetInterruptable(1)
	pWait.SetContainedAI(pStay)
	pWait.AddCondition(pDelay)
	pWait.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI Wait
	#########################################
	#########################################
	# Creating PlainAI WarpIn at (302, 143)
	pWarpIn = App.PlainAI_Create(pShip, "WarpIn")
	pWarpIn.SetScriptModule("Warp")
	pWarpIn.SetInterruptable(1)
	pScript = pWarpIn.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.Ascella.Ascella3")
	pScript.SetDestinationPlacementName(sPlacementName)
	pScript.WarpBlindly(1)
	# Done creating PlainAI WarpIn
	#########################################
	#########################################
	# Creating PlainAI ReinforcementsScript at (318, 107)
	pReinforcementsScript = App.PlainAI_Create(pShip, "ReinforcementsScript")
	pReinforcementsScript.SetScriptModule("RunScript")
	pReinforcementsScript.SetInterruptable(1)
	pScript = pReinforcementsScript.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode7.E7M3.E7M3")
	pScript.SetFunction("ReinforcementsArrived")
	# Done creating PlainAI ReinforcementsScript
	#########################################
	#########################################
	# Creating CompoundAI Attack at (334, 70)
	import AI.Compound.BasicAttack
	pAttack = AI.Compound.BasicAttack.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode7.E7M3.E7M3", "pFriendlies"))
	# Done creating CompoundAI Attack
	#########################################
	#########################################
	# Creating PlainAI Stay2 at (370, 35)
	pStay2 = App.PlainAI_Create(pShip, "Stay2")
	pStay2.SetScriptModule("Stay")
	pStay2.SetInterruptable(1)
	# Done creating PlainAI Stay2
	#########################################
	#########################################
	# Creating SequenceAI Sequence at (188, 35)
	pSequence = App.SequenceAI_Create(pShip, "Sequence")
	pSequence.SetInterruptable(1)
	pSequence.SetLoopCount(1)
	pSequence.SetResetIfInterrupted(1)
	pSequence.SetDoubleCheckAllDone(0)
	pSequence.SetSkipDormant(0)
	# SeqBlock is at (277, 42)
	pSequence.AddAI(pWait)
	pSequence.AddAI(pWarpIn)
	pSequence.AddAI(pReinforcementsScript)
	pSequence.AddAI(pAttack)
	pSequence.AddAI(pStay2)
	# Done creating SequenceAI Sequence
	#########################################
	#########################################
	# Creating PreprocessingAI RedAlert at (104, 55)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AlertLevel(App.ShipClass.RED_ALERT)
	## The PreprocessingAI:
	pRedAlert = App.PreprocessingAI_Create(pShip, "RedAlert")
	pRedAlert.SetInterruptable(1)
	pRedAlert.SetPreprocessingMethod(pScript, "Update")
	pRedAlert.SetContainedAI(pSequence)
	# Done creating PreprocessingAI RedAlert
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (20, 75)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pRedAlert)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
