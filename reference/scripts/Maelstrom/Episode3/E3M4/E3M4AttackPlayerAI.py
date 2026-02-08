import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI WarbirdsDestroyedScript at (69, 217)
	pWarbirdsDestroyedScript = App.PlainAI_Create(pShip, "WarbirdsDestroyedScript")
	pWarbirdsDestroyedScript.SetScriptModule("RunScript")
	pWarbirdsDestroyedScript.SetInterruptable(1)
	pScript = pWarbirdsDestroyedScript.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode3.E3M4.E3M4")
	pScript.SetFunction("WarbirdsDestroyed")
	# Done creating PlainAI WarbirdsDestroyedScript
	#########################################
	#########################################
	# Creating PlainAI Warpout at (159, 218)
	pWarpout = App.PlainAI_Create(pShip, "Warpout")
	pWarpout.SetScriptModule("Warp")
	pWarpout.SetInterruptable(1)
	# Done creating PlainAI Warpout
	#########################################
	#########################################
	# Creating SequenceAI Sequence at (99, 128)
	pSequence = App.SequenceAI_Create(pShip, "Sequence")
	pSequence.SetInterruptable(1)
	pSequence.SetLoopCount(1)
	pSequence.SetResetIfInterrupted(1)
	pSequence.SetDoubleCheckAllDone(0)
	pSequence.SetSkipDormant(0)
	# SeqBlock is at (124, 173)
	pSequence.AddAI(pWarbirdsDestroyedScript)
	pSequence.AddAI(pWarpout)
	# Done creating SequenceAI Sequence
	#########################################
	#########################################
	# Creating ConditionalAI IfWarbirdsDestroyed at (100, 89)
	## Conditions:
	#### Condition Warbird3Destroyed
	pWarbird3Destroyed = App.ConditionScript_Create("Conditions.ConditionDestroyed", "ConditionDestroyed", "Soryak")
	#### Condition Warbird4Destroyed
	pWarbird4Destroyed = App.ConditionScript_Create("Conditions.ConditionDestroyed", "ConditionDestroyed", "Chilvas")
	## Evaluation function:
	def EvalFunc(bWarbird3Destroyed, bWarbird4Destroyed):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bWarbird3Destroyed or bWarbird4Destroyed):
			return ACTIVE
		else:
			return DORMANT
	## The ConditionalAI:
	pIfWarbirdsDestroyed = App.ConditionalAI_Create(pShip, "IfWarbirdsDestroyed")
	pIfWarbirdsDestroyed.SetInterruptable(1)
	pIfWarbirdsDestroyed.SetContainedAI(pSequence)
	pIfWarbirdsDestroyed.AddCondition(pWarbird3Destroyed)
	pIfWarbirdsDestroyed.AddCondition(pWarbird4Destroyed)
	pIfWarbirdsDestroyed.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI IfWarbirdsDestroyed
	#########################################
	#########################################
	# Creating PlainAI WarbirdsDisabledScript at (186, 127)
	pWarbirdsDisabledScript = App.PlainAI_Create(pShip, "WarbirdsDisabledScript")
	pWarbirdsDisabledScript.SetScriptModule("RunScript")
	pWarbirdsDisabledScript.SetInterruptable(1)
	pScript = pWarbirdsDisabledScript.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode3.E3M4.E3M4")
	pScript.SetFunction("WarbirdsDisabled")
	pScript.SetArguments(pShip)
	# Done creating PlainAI WarbirdsDisabledScript
	#########################################
	#########################################
	# Creating ConditionalAI IfDisabled at (187, 89)
	## Conditions:
	#### Condition PhasersDisabled
	pPhasersDisabled = App.ConditionScript_Create("Conditions.ConditionSystemDisabled", "ConditionSystemDisabled", pShip.GetName (), App.CT_PHASER_SYSTEM, 1)
	#### Condition TorpedosDisabled
	pTorpedosDisabled = App.ConditionScript_Create("Conditions.ConditionSystemDisabled", "ConditionSystemDisabled", pShip.GetName (), App.CT_TORPEDO_SYSTEM, 1)
	#### Condition DisruptorsDisabled
	pDisruptorsDisabled = App.ConditionScript_Create("Conditions.ConditionSystemDisabled", "ConditionSystemDisabled", pShip.GetName (), App.CT_PULSE_WEAPON_SYSTEM, 1)
	#### Condition SensorsDisabled
	pSensorsDisabled = App.ConditionScript_Create("Conditions.ConditionSystemDisabled", "ConditionSystemDisabled", pShip.GetName (), App.CT_SENSOR_SUBSYSTEM, 1)
	## Evaluation function:
	def EvalFunc(bPhasersDisabled, bTorpedosDisabled, bDisruptorsDisabled, bSensorsDisabled):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bPhasersDisabled and bTorpedosDisabled and bDisruptorsDisabled) or bSensorsDisabled:
			return ACTIVE
		else:
			return DORMANT
	## The ConditionalAI:
	pIfDisabled = App.ConditionalAI_Create(pShip, "IfDisabled")
	pIfDisabled.SetInterruptable(1)
	pIfDisabled.SetContainedAI(pWarbirdsDisabledScript)
	pIfDisabled.AddCondition(pPhasersDisabled)
	pIfDisabled.AddCondition(pTorpedosDisabled)
	pIfDisabled.AddCondition(pDisruptorsDisabled)
	pIfDisabled.AddCondition(pSensorsDisabled)
	pIfDisabled.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI IfDisabled
	#########################################
	#########################################
	# Creating CompoundAI AttackPlayer at (276, 90)
	import AI.Compound.BasicAttack
	pAttackPlayer = AI.Compound.BasicAttack.CreateAI(pShip, "player")
	# Done creating CompoundAI AttackPlayer
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (101, 16)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (125, 54)
	pPriorityList.AddAI(pIfWarbirdsDestroyed, 1)
	pPriorityList.AddAI(pIfDisabled, 2)
	pPriorityList.AddAI(pAttackPlayer, 3)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (12, 16)
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
